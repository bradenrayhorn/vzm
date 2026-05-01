{
  description = "UEFI-bootable NixOS guest image for vzm";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs =
    { nixpkgs, ... }:
    let
      system = "aarch64-linux";
      pkgs = import nixpkgs { inherit system; };

      vm = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [ ./configuration.nix ];
      };

      guestImage = pkgs.runCommand "guest-image" { } ''
        mkdir -p "$out"

        cp ${vm.config.system.build.image}/${vm.config.image.filePath} "$out/${vm.config.image.fileName}"
        cp ${vm.config.system.build.image}/repart-output.json "$out/repart-output.json"
        printf '%s\n' '${vm.config.image.fileName}' > "$out/image-file-name.txt"
      '';
    in
    {
      nixosConfigurations = {
        vm = vm;
      };

      packages.${system} = {
        guest-image = guestImage;
        guest-bundle = guestImage;
      };
    };
}
