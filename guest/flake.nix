{
  description = "Direct-boot NixOS guest bundle for vzm";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs =
    { self, nixpkgs, ... }:
    let
      system = "aarch64-linux";
      pkgs = import nixpkgs { inherit system; };

      vm = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [ self.nixosModules.default ];
      };

      rootfsImage = pkgs.callPackage "${nixpkgs}/nixos/lib/make-squashfs.nix" {
        storeContents = [ vm.config.system.build.toplevel ];
      };

      kernelCommandLine = nixpkgs.lib.concatStringsSep " " (
        [
          # The initrd mounts / as tmpfs from fileSystems."/", then mounts
          # /dev/vda (rootfs.squashfs) as the immutable /nix/store lowerdir.
          "init=${vm.config.system.build.toplevel}/init"
        ]
        ++ vm.config.boot.kernelParams
      );

      guestManifest = pkgs.writeText "manifest.json" (builtins.toJSON {
        schemaVersion = 1;
        architecture = "aarch64";
        kernel = "kernel";
        initrd = "initrd";
        rootfs = "rootfs.squashfs";
        rootMode = "immutable";
        commandLine = kernelCommandLine;
      });

      guestBundle = pkgs.runCommand "guest-bundle" { } ''
        mkdir -p "$out"

        cp ${vm.config.system.build.kernel}/${vm.config.system.boot.loader.kernelFile} "$out/kernel"

        initrd_source=${vm.config.system.build.initialRamdisk}
        if [ -d "$initrd_source" ]; then
          cp "$initrd_source"/initrd "$out/initrd"
        else
          cp "$initrd_source" "$out/initrd"
        fi

        cp ${rootfsImage} "$out/rootfs.squashfs"
        cp ${guestManifest} "$out/manifest.json"
      '';
    in
    {
      nixosModules = {
        base = import ./base.nix;
        braden = import ./braden.nix;
        default = import ./configuration.nix;
      };

      nixosConfigurations = {
        vm = vm;
      };

      packages.${system} = {
        default = guestBundle;
        guest-bundle = guestBundle;
      };
    };
}
