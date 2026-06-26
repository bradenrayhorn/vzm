{ modulesPath, pkgs, lib, nixpkgs, ... }:
{
  imports = [
    (modulesPath + "/profiles/qemu-guest.nix")
    ./proxy.nix
    ./git-proxy.nix
    ./port-expose.nix
    ./disks.nix
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
      AllowAgentForwarding = false;
    };
  };

  security.sudo.wheelNeedsPassword = false;

  # -- boot
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
  boot.kernelPackages = pkgs.linuxPackages;
  boot.supportedFilesystems.zfs = lib.mkForce false;
  boot.loader.grub.enable = false;
  boot.loader.systemd-boot.enable = false;
  boot.loader.efi.canTouchEfiVariables = false;
  boot.kernelModules = [ ];
  boot.extraModulePackages = [ ];

  nixpkgs.hostPlatform = lib.mkDefault "aarch64-linux";

  networking.useDHCP = false;
  networking.hostName = "vzm-guest";
  networking.interfaces = { };
  networking.firewall.enable = lib.mkForce false; # there is no network mounted

  environment.systemPackages = with pkgs; [
    vim
    git
    ghostty.terminfo
  ];

  nixpkgs.config.allowUnfree = true;

  environment.variables = {
    EDITOR = "vim";
  };

  programs.zsh.enable = true;
  users.defaultUserShell = pkgs.zsh;

  time.timeZone = "America/Chicago";

  # pin nixpkgs registry to same instance used to build guest
  nix.registry.nixpkgs.flake = nixpkgs;
  nix.nixPath = [ "nixpkgs=${nixpkgs}" ];

  nix.gc.automatic = false;

  system.stateVersion = "26.05";
}
