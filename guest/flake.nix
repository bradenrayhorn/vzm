{
  description = "Direct-boot NixOS guest bundle for vzm";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs =
    { self, nixpkgs, ... }:
    let
      defaultSystem = "aarch64-linux";
      defaultNixpkgs = nixpkgs;

      mkGuestSystem =
        {
          system ? defaultSystem,
          nixpkgs ? defaultNixpkgs,
          modules,
          specialArgs ? { }
        }:
        nixpkgs.lib.nixosSystem {
          inherit system modules specialArgs;
        };

      mkGuestBundle =
        {
          system ? defaultSystem,
          nixpkgs ? defaultNixpkgs,
          modules ? null,
          specialArgs ? { },
          nixosConfiguration ? null,
          pkgs ? null
        }:
        let
          vm =
            if nixosConfiguration != null then
              nixosConfiguration
            else if modules != null then
              mkGuestSystem {
                inherit system nixpkgs modules specialArgs;
              }
            else
              throw "vzm-guest.lib.mkGuestBundle: pass either `modules` or `nixosConfiguration`.";

          resolvedPkgs = if pkgs != null then pkgs else vm.pkgs or (import nixpkgs { inherit system; });
          nixpkgsPath = if resolvedPkgs ? path then resolvedPkgs.path else nixpkgs;

          rootfsImage = resolvedPkgs.callPackage "${nixpkgsPath}/nixos/lib/make-squashfs.nix" {
            storeContents = [ vm.config.system.build.toplevel ];
          };

          kernelCommandLine = resolvedPkgs.lib.concatStringsSep " " (
            [
              # The initrd mounts / as tmpfs from fileSystems."/", then mounts
              # /dev/vda (rootfs.squashfs) as the immutable /nix/store lowerdir.
              "init=${vm.config.system.build.toplevel}/init"
            ]
            ++ vm.config.boot.kernelParams
          );

          guestManifest = resolvedPkgs.writeText "manifest.json" (builtins.toJSON {
            schemaVersion = 1;
            architecture = "aarch64";
            kernel = "kernel";
            initrd = "initrd";
            rootfs = "rootfs.squashfs";
            rootMode = "immutable";
            commandLine = kernelCommandLine;
          });
        in
        resolvedPkgs.runCommand "guest-bundle" { } ''
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

      vm = mkGuestSystem {
        modules = [ self.nixosModules.default ];
      };

      guestBundle = mkGuestBundle {
        nixosConfiguration = vm;
      };
    in
    {
      lib = {
        inherit mkGuestSystem mkGuestBundle;
      };

      nixosModules = {
        base = import ./base.nix;
        braden = import ./braden.nix;
        default = import ./configuration.nix;
      };

      nixosConfigurations = {
        vm = vm;
      };

      packages.${defaultSystem} = {
        default = guestBundle;
        guest-bundle = guestBundle;
      };
    };
}
