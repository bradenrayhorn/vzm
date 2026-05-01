{
  modulesPath,
  pkgs,
  lib,
  config,
  ...
}:
{
  imports = [
    (modulesPath + "/profiles/qemu-guest.nix")
    (modulesPath + "/image/repart.nix")
  ];

  nix.settings.experimental-features = [
    "nix-command"
    "flakes"
  ];

  programs.nix-ld.enable = true;

  services.openssh = {
    enable = true;
    startWhenNeeded = lib.mkForce false;
    settings = {
      PermitRootLogin = "no";
      PasswordAuthentication = false;
      KbdInteractiveAuthentication = false;
      AllowUsers = [ "braden" ];
      AllowAgentForwarding = true;
    };
  };

  programs.ssh.extraConfig = ''
    Host github.com
      HostName github.com
      Port 22
      ProxyCommand ${pkgs.socat}/bin/socat - VSOCK-CONNECT:2:2223
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
  boot.loader.systemd-boot.enable = true;
  boot.loader.systemd-boot.configurationLimit = 10;
  boot.loader.systemd-boot.editor = false;
  boot.loader.efi.canTouchEfiVariables = false;
  boot.loader.efi.efiSysMountPoint = "/boot";

  boot.initrd.availableKernelModules = [
    "virtio_blk"
    "virtio_pci"
    "virtio_scsi"
    "xhci_pci"
    "usbhid"
    "usb_storage"
    "sr_mod"
  ];
  boot.initrd.kernelModules = [
    "virtiofs"
    "vsock"
    "vmw_vsock_virtio_transport"
  ];
  boot.kernelModules = [
    "vsock"
    "vmw_vsock_virtio_transport"
  ];
  boot.extraModulePackages = [ ];

  nixpkgs.hostPlatform = lib.mkDefault "aarch64-linux";

  boot.kernelPackages = pkgs.linuxPackages_latest;
  boot.supportedFilesystems.zfs = lib.mkForce false;

  fileSystems."/" = {
    device = "/dev/disk/by-partlabel/vzm-root";
    fsType = "ext4";
  };

  fileSystems."/boot" = {
    device = "/dev/disk/by-partlabel/vzm-esp";
    fsType = "vfat";
  };

  image.repart = {
    name = "vzm-guest";
    compression = {
      enable = true;
      algorithm = "zstd";
      level = 10;
    };
    partitions = {
      "10-esp" = {
        contents = {
          # Seed the ESP for first boot. Afterwards, NixOS/systemd-boot manages
          # /boot across rebuilds and writes generation-specific entries.
          "/EFI/BOOT/BOOTAA64.EFI".source = "${pkgs.systemd}/lib/systemd/boot/efi/systemd-bootaa64.efi";
          "/EFI/systemd/systemd-bootaa64.efi".source =
            "${pkgs.systemd}/lib/systemd/boot/efi/systemd-bootaa64.efi";
          "/EFI/nixos/initial-kernel.efi".source =
            "${config.system.build.kernel}/${config.system.boot.loader.kernelFile}";
          "/EFI/nixos/initial-initrd.efi".source =
            "${config.system.build.initialRamdisk}/${config.system.boot.loader.initrdFile}";
          "/loader/loader.conf".source = pkgs.writeText "loader.conf" ''
            default nixos-initial.conf
            timeout 3
            editor 0
            console-mode keep
          '';
          "/loader/entries/nixos-initial.conf".source = pkgs.writeText "nixos-initial.conf" ''
            title NixOS (initial)
            linux /EFI/nixos/initial-kernel.efi
            initrd /EFI/nixos/initial-initrd.efi
            options init=${config.system.build.toplevel}/init root=PARTLABEL=vzm-root rootfstype=ext4 ${lib.concatStringsSep " " config.boot.kernelParams}
          '';
        };
        repartConfig = {
          Type = "esp";
          Label = "vzm-esp";
          Format = "vfat";
          SizeMinBytes = "256M";
        };
      };
      "20-root" = {
        storePaths = [ config.system.build.toplevel ];
        repartConfig = {
          Type = "root";
          Label = "vzm-root";
          Format = "ext4";
          Minimize = "guess";
          SizeMinBytes = "2G";
          MakeDirectories = [
            "/boot"
            "/data"
            "/dev"
            "/proc"
            "/sys"
            "/run"
            "/tmp"
          ];
        };
      };
    };
  };

  networking.useDHCP = false;
  networking.hostName = "vzm-guest";
  networking.interfaces = { };
  networking.firewall.enable = true;
  networking.firewall.allowedTCPPorts = [ 22 ];

  environment.systemPackages = with pkgs; [
    socat
    vim
  ];

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

  environment.etc."skel/.zshrc".text = ''
    # Prevent zsh-newuser-install from hijacking the console on first login.
  '';

  boot.postBootCommands = ''
    if [ -f /nix-path-registration ]; then
      ${config.nix.package.out}/bin/nix-store --load-db < /nix-path-registration
      rm /nix-path-registration
    fi
  ''
  + ''
    ${config.nix.package.out}/bin/nix-env -p /nix/var/nix/profiles/system --set /run/current-system
  '';

  system.stateVersion = "25.11";
}
