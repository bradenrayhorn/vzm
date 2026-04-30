{
  description = "Swift CLI environment";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-25.11";

  outputs =
    { self, nixpkgs }:
    let
      # Change "aarch64-linux" to "x86_64-linux" or "aarch64-darwin" if needed
      system = "aarch64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        name = "swift-env";
        packages = [
          pkgs.swift
          pkgs.swiftpm
          pkgs.swift-format
        ];
      };
    };
}
