{
  description = "dcompass project";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nmattia/naersk";
  };

  outputs = { nixpkgs, rust-overlay, utils, naersk, ... }:
    with nixpkgs.lib;
    let
      features = [ "geoip-maxmind" "geoip-cn" ];
      forEachFeature = f:
        builtins.listToAttrs (map (v:
          attrsets.nameValuePair "dcompass-${strings.removePrefix "geoip-" v}"
          (f v)) features);
      pkgSet = lib:
        forEachFeature (v:
          lib.buildPackage {
            name = "dcompass-${strings.removePrefix "geoip-" v}";
            version = "git";
            root = ./.;
            cargoBuildOptions = default:
              (default ++ [
                "--manifest-path ./dcompass/Cargo.toml"
                ''--features "${v}"''
              ]);
          });
    in utils.lib.eachDefaultSystem (system: rec {
      # `nix build`
      packages = (pkgSet naersk.lib."${system}");

      defaultPackage = packages.dcompass-maxmind;

      checks = packages;

      # `nix run`
      apps = (forEachFeature (v:
        utils.lib.mkApp {
          drv = packages."dcompass-${strings.removePrefix "geoip-" v}";
        }));
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
    }) // {
      # public key for dcompass.cachix.org
      publicKey =
        "dcompass.cachix.org-1:uajJEJ1U9uy/y260jBIGgDwlyLqfL1sD5yaV/uWVlbk=";

      overlay = final: prev: {
        dcompass = recurseIntoAttrs (pkgSet naersk.lib."${prev.pkgs.system}");
      };
    };
}
