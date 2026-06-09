{
  modulesPath,
  pkgs,
  lib,
  config,
  builderAgent,
  ...
}:
{
  imports = [
    (modulesPath + "/profiles/qemu-guest.nix")
  ];

  nixpkgs.hostPlatform = lib.mkDefault "aarch64-linux";
  system.stateVersion = "25.11";

  boot.loader.grub.enable = false;
  boot.loader.systemd-boot.enable = false;
  boot.loader.efi.canTouchEfiVariables = false;
  boot.kernelPackages = pkgs.linuxPackages_latest;
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

  # The host should attach a blank writable disk as /dev/vdb.  Stage 1 formats
  # it on first boot and uses it as the overlay upper/workdir for /nix/store so
  # Nix builds do not consume the VM's RAM-backed root filesystem.
  boot.initrd.extraUtilsCommands = ''
    copy_bin_and_libs ${pkgs.e2fsprogs}/bin/mke2fs
    copy_bin_and_libs ${pkgs.e2fsprogs}/bin/mkfs.ext4
    copy_bin_and_libs ${pkgs.util-linux}/bin/blkid
  '';

  boot.initrd.postDeviceCommands = lib.mkBefore ''
    if [ ! -b /dev/vdb ]; then
      echo "vzm-builder: missing writable work disk at /dev/vdb" >&2
      exit 1
    fi

    if ! blkid /dev/vdb >/dev/null 2>&1; then
      echo "vzm-builder: formatting /dev/vdb as ext4"
      mkfs.ext4 -F -L vzm-work /dev/vdb
    fi

    mkdir -p /tmp/vzm-rw-store
    mount -t ext4 /dev/vdb /tmp/vzm-rw-store
    mkdir -p /tmp/vzm-rw-store/store /tmp/vzm-rw-store/work
    umount /tmp/vzm-rw-store
  '';

  fileSystems."/" = {
    device = "none";
    fsType = "tmpfs";
    options = [ "mode=0755" ];
  };

  fileSystems."/nix/.ro-store" = {
    device = "/dev/vda";
    fsType = "squashfs";
    options = [ "ro" ];
    neededForBoot = true;
  };

  fileSystems."/nix/.rw-store" = {
    device = "/dev/vdb";
    fsType = "ext4";
    options = [ "rw" "noatime" ];
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
    wantedBy = [ "sysinit.target" ];
    before = [
      "sysinit.target"
      "shutdown.target"
      "nix-daemon.socket"
      "nix-daemon.service"
    ];
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
