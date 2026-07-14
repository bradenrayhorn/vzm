{
  modulesPath,
  pkgs,
  lib,
  config,
  utils,
  builderAgent,
  ...
}:
let
  rootDevice = "/dev/disk/by-id/virtio-vzm-root";
  rootDeviceUnit = "${utils.escapeSystemdPath rootDevice}.device";
  rootFsckUnit = "systemd-fsck-root.service";
in
{
  imports = [
    (modulesPath + "/profiles/qemu-guest.nix")
  ];

  nixpkgs.hostPlatform = lib.mkDefault "aarch64-linux";
  system.stateVersion = "26.05";

  boot.loader.grub.enable = false;
  boot.loader.systemd-boot.enable = false;
  boot.loader.efi.canTouchEfiVariables = false;
  boot.kernelPackages = pkgs.linuxPackages;
  boot.supportedFilesystems.zfs = lib.mkForce false;

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
    "overlay"
  ];
  boot.kernelModules = [
    "virtiofs"
    "vsock"
    "vmw_vsock_virtio_transport"
  ];
  boot.extraModulePackages = [ ];

  # Ephemeral root: vzm attaches a fresh sparse host-backed disk for each build.
  # Systemd stage 1 formats it if needed and mounts it as the writable root.
  boot.initrd.systemd.extraBin = {
    blkid = "${pkgs.util-linux}/bin/blkid";
    mke2fs = "${pkgs.e2fsprogs}/bin/mke2fs";
    "mkfs.ext4" = "${pkgs.e2fsprogs}/bin/mkfs.ext4";
  };

  boot.initrd.systemd.services.vzm-format-root = {
    description = "Format vzm builder ephemeral root disk";
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
        echo "vzm-builder: missing ephemeral root disk at $root_device" >&2
        exit 1
      fi

      if ! blkid "$root_device" >/dev/null 2>&1; then
        echo "vzm-builder: formatting ephemeral root disk"
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

  fileSystems."/nix/.ro-store" = {
    device = "/dev/vda";
    fsType = "squashfs";
    options = [ "ro" ];
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

  # The host will expose a VZ virtiofs share with tag "vzm-builder".  It should
  # contain request.json, source/, and output/.
  fileSystems."/run/vzm-builder" = {
    device = "vzm-builder";
    fsType = "virtiofs";
    options = [ "rw" "nofail" ];
  };

  systemd.tmpfiles.rules = [
    "d /run/vzm-builder 0755 root root -"
  ];

  nix.settings = {
    experimental-features = [
      "nix-command"
      "flakes"
    ];
    accept-flake-config = true;
    trusted-users = [ "root" ];
    max-jobs = "auto";
    cores = 0;
  };

  programs.nix-ld.enable = true;
  environment.systemPackages = with pkgs; [
    builderAgent
    cacert
    curl
    git
    jq
    vim
  ];

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

  networking.useDHCP = true;
  networking.hostName = "vzm-builder";
  networking.firewall.enable = true;

  services.openssh.enable = false;

  systemd.services.vzm-builder = {
    description = "Build a vzm guest bundle from the shared request";
    wantedBy = [ "multi-user.target" ];
    wants = [ "network-online.target" ];
    requires = [ "run-vzm\\x2dbuilder.mount" ];
    after = [
      "network-online.target"
      "run-vzm\\x2dbuilder.mount"
      "nix-daemon.socket"
    ];
    restartIfChanged = false;
    serviceConfig = {
      Type = "oneshot";
      StandardOutput = "journal+console";
      StandardError = "journal+console";
    };
    script = ''
      ${lib.getExe builderAgent}
    '';
  };
}
