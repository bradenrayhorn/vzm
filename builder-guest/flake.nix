{
  description = "Direct-boot NixOS guest-builder bundle for vzm";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs =
    { nixpkgs, ... }:
    let
      system = "aarch64-linux";
      lib = nixpkgs.lib;
      pkgs = import nixpkgs { inherit system; };

      builderAgent = pkgs.writeShellApplication {
        name = "vzm-builder-agent";
        runtimeInputs = with pkgs; [
          coreutils
          findutils
          jq
          nix
          util-linux
        ];
        text = builtins.readFile ./builder-agent.sh;
      };

      vm = lib.nixosSystem {
        inherit system;
        specialArgs = { inherit builderAgent; };
        modules = [ ./configuration.nix ];
      };

      rootfsImage = pkgs.callPackage "${nixpkgs}/nixos/lib/make-squashfs.nix" {
        storeContents = [ vm.config.system.build.toplevel ];
      };

      kernelCommandLine = lib.concatStringsSep " " (
        [
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

      builderGuestBundle = pkgs.runCommand "builder-guest-bundle" { } ''
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
      nixosConfigurations = {
        builder = vm;
      };

      packages.${system} = {
        default = builderGuestBundle;
        guest-bundle = builderGuestBundle;
        builder-guest-bundle = builderGuestBundle;
      };
    };
}
