{
  modulesPath,
  pkgs,
  lib,
  config,
  ...
}:
let
  gitProxyVsockPort = 4022;
  vzmGitSSH = pkgs.writeShellScriptBin "vzm-git-ssh" ''
    set -eu
    [ "$#" -eq 2 ] || exit 1
    case "$1" in git@*) host="''${1#git@}" ;; *) exit 1 ;; esac

    req="$2"; service="''${req%% *}"; repo="''${req#* }"
    repo="''${repo#\'}"; repo="''${repo%\'}"; repo="''${repo#/}"
    case "$service" in git-upload-pack|git-receive-pack) ;; *) exit 1 ;; esac

    payload="$service /$host:$repo"
    { printf '%04x%s\0' "$(( ''${#payload} + 5 ))" "$payload"; ${pkgs.coreutils}/bin/cat; } \
      | exec ${pkgs.socat}/bin/socat -t3600 - VSOCK-CONNECT:2:${toString gitProxyVsockPort}
  '';
in
{
  imports = [
    (modulesPath + "/profiles/qemu-guest.nix")
    ./proxy.nix
    ./port-expose.nix
  ];

  nix.settings.experimental-features = [
    "nix-command"
    "flakes"
  ];

  programs.nix-ld.enable = true;

  services.openssh = {
    enable = true;
    startWhenNeeded = lib.mkForce false;
    hostKeys = [
      {
        bits = 4096;
        path = "/persist/etc/ssh/ssh_host_rsa_key";
        type = "rsa";
      }
      {
        path = "/persist/etc/ssh/ssh_host_ed25519_key";
        type = "ed25519";
      }
    ];
    settings = {
      PermitRootLogin = "no";
      PasswordAuthentication = false;
      KbdInteractiveAuthentication = false;
      AllowUsers = [ "braden" ];
      AllowAgentForwarding = false;
    };
  };

  environment.etc."gitconfig".text = ''
[core]
  sshCommand = ${vzmGitSSH}/bin/vzm-git-ssh
[ssh]
  variant = simple
  '';

  security = {
    sudo.wheelNeedsPassword = false;
    pam.enableUMask = true;
    loginDefs.settings.UMASK = "007";
  };

  systemd.user.extraConfig = ''
    DefaultUMask=0007
  '';

  boot.loader.grub.enable = false;
  boot.loader.systemd-boot.enable = false;
  boot.loader.efi.canTouchEfiVariables = false;

  boot.initrd.availableKernelModules = [
    "virtio_blk"
    "virtio_pci"
    "virtio_scsi"
    "xhci_pci"
    "usbhid"
    "usb_storage"
    "sr_mod"
    "overlay"
    "squashfs"
    "ext4"
  ];
  boot.initrd.kernelModules = [
    "virtiofs"
    "virtio_rng"
    "vsock"
    "vmw_vsock_virtio_transport"
    "overlay"
  ];

  boot.kernelModules = [];
  boot.extraModulePackages = [ ];

  nixpkgs.hostPlatform = lib.mkDefault "aarch64-linux";

  boot.kernelPackages = pkgs.linuxPackages_latest;
  boot.supportedFilesystems.zfs = lib.mkForce false;

  # Ephemeral root: stage 1 mounts this tmpfs at /mnt-root, then mounts the
  # immutable squashfs Nix store below before switching to stage 2.
  fileSystems."/" = {
    device = "none";
    fsType = "tmpfs";
    options = [ "mode=0755" ];
  };

  # The per-VM state disk is attached by vzm as virtio-vzm-state. It is not
  # needed by stage 1, so systemd can format and mount it during normal boot.
  fileSystems."/persist" = {
    device = "/dev/disk/by-id/virtio-vzm-state";
    fsType = "ext4";
    autoFormat = true;
  };

  # The VM attaches rootfs.squashfs as /dev/vda.  The image produced by
  # nixos/lib/make-squashfs.nix contains the closure as store entries at the
  # filesystem root, so mount it as the lowerdir for /nix/store rather than as
  # the final root filesystem.
  fileSystems."/nix/.ro-store" = {
    device = "/dev/vda";
    fsType = "squashfs";
    options = [ "ro" ];
    neededForBoot = true;
  };

  # Ephemeral writable layer for the Nix store and /nix/var.  Anything built or
  # registered at runtime disappears on reboot; the squashfs lowerdir remains
  # immutable.
  fileSystems."/nix/.rw-store" = {
    device = "none";
    fsType = "tmpfs";
    options = [ "mode=0755" ];
    neededForBoot = true;
  };

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

  # sshd uses host keys stored under /persist.  /persist is mounted by
  # local-fs.target before normal services, and this explicit ordering keeps
  # that requirement local to sshd instead of making vzm-mounts block sshd.
  systemd.services.sshd = {
    requires = [ "persist.mount" ];
    after = lib.mkForce [ "persist.mount" ];
  };

  networking.useDHCP = false;
  networking.hostName = "vzm-guest";
  networking.interfaces = { };
  networking.firewall.enable = lib.mkForce false;
  networking.firewall.allowedTCPPorts = [ 22 ];

  environment.systemPackages = with pkgs; [
    git
    socat
    vim
    vzmGitSSH
  ];

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

  nixpkgs.config.allowUnfree = true;

  environment.variables = {
    EDITOR = "vim";
  };

  programs.zsh.enable = true;
  users.defaultUserShell = pkgs.zsh;

  time.timeZone = "America/Chicago";

  nix.gc = {
    automatic = true;
    dates = "weekly";
    options = "--delete-older-than 7d";
  };

  users.groups.braden = { };

  users.users.braden = {
    isNormalUser = true;
    home = "/home/braden";
    homeMode = "700";
    createHome = true;
    group = "braden";
    extraGroups = [ "wheel" ];
    openssh.authorizedKeys.keys = [
      "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMxUPJoiKdlvEq4+i4ZCl7lj1NOSgT7BsspqfgncdJKQVV5CKVZ1hnn/MNO4cAXRFOWjXkzowN+7mJZm8cVhP18="
    ];
  };

  system.stateVersion = "25.11";
}
