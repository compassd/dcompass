{
  description = "dcompass project";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nmattia/naersk";
  };

  outputs = { nixpkgs, rust-overlay, utils, naersk, ... }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages."${system}";
        naersk-lib = naersk.lib."${system}";
        features = [ "geoip-maxmind" "geoip-cn" ];
        forEachFeature = f:
          (with nixpkgs.lib;
            (builtins.listToAttrs (map (v:
              attrsets.nameValuePair
              "dcompass-${strings.removePrefix "geoip-" v}"
              (f (strings.removePrefix "geoip-" v))) features)));
      in rec {
        # `nix build`
        packages = (forEachFeature (v:
          naersk-lib.buildPackage {
            name = "dcompass-${v}";
            version = "git";
            root = ./.;
            cargoBuildOptions = default:
              (default ++ [
                "--manifest-path ./dcompass/Cargo.toml"
                ''--features "${v}"''
              ]);
          }));
        defaultPackage = packages.dcompass-maxmind;

        # `nix run`
        apps = (forEachFeature
          (v: utils.lib.mkApp { drv = packages."dcompass-${v}"; }));
        defaultApp = apps.dcompass-maxmind;

        # `nix develop`
        devShell = with import nixpkgs {
          system = "${system}";
          overlays = [ rust-overlay.overlay ];
        };
          mkShell {
            nativeBuildInputs = [
              # write rustfmt first to ensure we are using nightly rustfmt
              rust-bin.nightly."2021-01-01".rustfmt
              rust-bin.stable.latest.rust
              binutils-unwrapped
            ];
          };
      });
}
