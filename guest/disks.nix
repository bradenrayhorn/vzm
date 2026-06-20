{ pkgs, lib, config, utils, ... }:
let
  rootDevice = "/dev/disk/by-id/virtio-vzm-root";
  rootDeviceUnit = "${utils.escapeSystemdPath rootDevice}.device";
  rootFsckUnit = "systemd-fsck-root.service";
in
{
  # Ephemeral root: vzm attaches a fresh sparse host-backed disk for each run.
  # Systemd stage 1 formats it if needed, mounts it at /sysroot, then mounts the
  # immutable squashfs Nix store below before switching to stage 2.
  boot.initrd.systemd.extraBin = {
    blkid = "${pkgs.util-linux}/bin/blkid";
    mke2fs = "${pkgs.e2fsprogs}/bin/mke2fs";
    "mkfs.ext4" = "${pkgs.e2fsprogs}/bin/mkfs.ext4";
  };

  boot.initrd.systemd.services.vzm-format-root = {
    description = "Format vzm ephemeral root disk";
    requiredBy = [ "sysroot.mount" ];
    requires = [ rootDeviceUnit ];
    after = [ rootDeviceUnit ];
    before = [
      rootFsckUnit
      "sysroot.mount"
      "shutdown.target"
    ];
    conflicts = [ "shutdown.target" ];
    unitConfig.DefaultDependencies = false;
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      root_device=${lib.escapeShellArg rootDevice}

      if [ ! -b "$root_device" ]; then
        echo "vzm: missing ephemeral root disk at $root_device" >&2
        exit 1
      fi

      if ! blkid "$root_device" >/dev/null 2>&1; then
        echo "vzm: formatting ephemeral root disk"
        mkfs.ext4 -F -L vzm-root "$root_device"
      fi
    '';
  };

  fileSystems."/" = {
    device = rootDevice;
    fsType = "ext4";
    options = [ "rw" "noatime" ];
    neededForBoot = true;
  };

  # The per-VM state disk is attached by vzm as virtio-vzm-state. It is not
  # needed by stage 1, so systemd can format and mount it during normal boot.
  fileSystems."/persist" = {
    device = "/dev/disk/by-id/virtio-vzm-state";
    fsType = "ext4";
    autoFormat = true;
  };

  # The VM attaches rootfs.squashfs as /dev/vda. The image produced by
  # nixos/lib/make-squashfs.nix contains the closure as store entries at the
  # filesystem root, so mount it as the lowerdir for /nix/store rather than as
  # the final root filesystem.
  fileSystems."/nix/.ro-store" = {
    device = "/dev/vda";
    fsType = "squashfs";
    options = [ "ro" ];
    neededForBoot = true;
  };

  # Ephemeral writable layer for the Nix store and /nix/var. This lives on the
  # host-backed ephemeral root disk, so builds do not consume VM RAM. Anything
  # built or registered at runtime disappears on reboot; the squashfs lowerdir
  # remains immutable.
  fileSystems."/nix/store" = {
    overlay = {
      lowerdir = [ "/nix/.ro-store" ];
      upperdir = "/nix/.rw-store/store";
      workdir = "/nix/.rw-store/work";
    };
    neededForBoot = true;
  };

  systemd.services.register-nix-store = {
    description = "Register immutable squashfs Nix store paths";
    unitConfig.DefaultDependencies = false;
    wantedBy = [ "multi-user.target" ];
    before = [ "shutdown.target" ];
    after = [ "local-fs.target" ];
    conflicts = [ "shutdown.target" ];
    restartIfChanged = false;
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      ${lib.getExe' config.nix.package "nix-store"} --load-db < /nix/store/nix-path-registration
      touch /etc/NIXOS
      ${lib.getExe' config.nix.package "nix-env"} -p /nix/var/nix/profiles/system --set /run/current-system
    '';
  };

  systemd.services.nix-daemon = {
    requires = [ "register-nix-store.service" ];
    after = [ "register-nix-store.service" ];
  };

  # sshd uses host keys stored under /persist. /persist is mounted by
  # local-fs.target before normal services, and this explicit ordering keeps
  # that requirement local to sshd instead of making vzm-mounts block sshd.
  systemd.services.sshd = {
    requires = [ "persist.mount" ];
    after = lib.mkForce [ "persist.mount" ];
  };

  systemd.services.vzm-mounts = {
    description = "Mount vzm shared directories and disks";
    wantedBy = [ "multi-user.target" ];
    before = [ "multi-user.target" ];
    after = [ "local-fs.target" ];
    restartIfChanged = false;
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      set -eu

      for token in $(${pkgs.coreutils}/bin/cat /proc/cmdline); do
        case "$token" in
          vzm.share=*)
            spec="''${token#vzm.share=}"
            tag="''${spec%%:*}"
            mount_path="''${spec#*:}"

            if [ -z "$tag" ] || [ -z "$mount_path" ] || [ "$tag" = "$spec" ]; then
              echo "vzm-mounts: invalid share spec: $spec" >&2
              exit 1
            fi

            ${pkgs.coreutils}/bin/mkdir -p "$mount_path"

            if ${pkgs.gnugrep}/bin/grep -Fqs " $mount_path virtiofs " /proc/mounts; then
              continue
            fi

            ${pkgs.util-linux}/bin/mount -t virtiofs "$tag" "$mount_path"
            ;;
          vzm.disk=*)
            spec="''${token#vzm.disk=}"
            name="''${spec%%:*}"
            rest="''${spec#*:}"
            filesystem="''${rest%%:*}"
            mount_path="''${rest#*:}"
            device="/dev/disk/by-id/virtio-$name"

            if [ -z "$name" ] || [ -z "$filesystem" ] || [ -z "$mount_path" ] || [ "$name" = "$spec" ] || [ "$rest" = "$spec" ] || [ "$mount_path" = "$rest" ]; then
              echo "vzm-mounts: invalid disk spec: $spec" >&2
              exit 1
            fi

            if [ ! -b "$device" ]; then
              echo "vzm-mounts: missing disk device for $name at $device" >&2
              exit 1
            fi

            if ! ${pkgs.util-linux}/bin/blkid "$device" >/dev/null 2>&1; then
              case "$filesystem" in
                ext4)
                  ${pkgs.e2fsprogs}/bin/mkfs.ext4 -F "$device"
                  ;;
                *)
                  echo "vzm-mounts: unsupported filesystem $filesystem for disk $name" >&2
                  exit 1
                  ;;
              esac
            fi

            ${pkgs.coreutils}/bin/mkdir -p "$mount_path"

            if ! ${pkgs.gnugrep}/bin/grep -Fqs " $mount_path $filesystem " /proc/mounts; then
              ${pkgs.util-linux}/bin/mount -t "$filesystem" "$device" "$mount_path"
            fi

            ${pkgs.coreutils}/bin/chown braden:braden "$mount_path"
            ;;
        esac
      done
    '';
  };
}
