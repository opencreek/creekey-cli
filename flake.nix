{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    crane.url = "github:ipetkov/crane";
  };

  outputs = {
    nixpkgs,
    crane,
    ...
  }: let
    systems = ["x86_64-linux"];
    perSystem = f:
      nixpkgs.lib.foldAttrs nixpkgs.lib.mergeAttrs {}
      (map (s: nixpkgs.lib.mapAttrs (_: v: {${s} = v;}) (f s)) systems);
  in
    perSystem (system: let
      pkgs = import nixpkgs {inherit system;};
      craneLib = crane.mkLib pkgs;

      src = craneLib.cleanCargoSource ./.;

      args = {
        inherit src;
        strictDeps = true;
        nativeBuildInputs = with pkgs; [pkg-config];
        buildInputs = with pkgs; [
          openssl
          libsodium
          libsecret
        ];
      };

      cargoArtifacts = craneLib.buildDepsOnly args;

      package = craneLib.buildPackage (args
        // {
          inherit cargoArtifacts;
        });
    in {
      devShells.default = craneLib.devShell {
        packages = with pkgs;
          [rust-analyzer]
          ++ (with args; (nativeBuildInputs ++ buildInputs));
      };

      packages.default = package;
    });
}
