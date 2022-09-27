{
  description = "dcompass project";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, rust-overlay, utils, ... }:
    with nixpkgs.lib;
    let
      pkgsWithRust = system:
        import nixpkgs {
          system = "${system}";
          overlays = [ rust-overlay.overlays.default ];
        };
      features = [ "geoip-maxmind" "geoip-cn" ];
      forEachFeature = f:
        builtins.listToAttrs (map (v:
          attrsets.nameValuePair "dcompass-${strings.removePrefix "geoip-" v}"
          (f v)) features);
      pkgSet = system:
        forEachFeature (v:
          with (pkgsWithRust system);
          (makeRustPlatform {
            cargo = rust-bin.stable.latest.default;
            rustc = rust-bin.stable.latest.default;
          }).buildRustPackage {
            name = "dcompass-${strings.removePrefix "geoip-" v}";
            version = "git";
            src = lib.cleanSource ./.;
            cargoLock = {
              lockFile = ./Cargo.lock;
              outputHashes = {
                "cidr-utils-0.5.7" =
                  "sha256-Kyvq1R5o7csR2BGWj9oZ6J+96fSqNBXBB2m/79HjGbM=";
              };
            };
            cargoBuildFlags = [ "--features ${v}" ];
            nativeBuildInputs = [ pkg-config openssl ];
          });
    in utils.lib.eachSystem (with utils.lib.system; [
      aarch64-linux
      i686-linux
      x86_64-darwin
      x86_64-linux
    ]) (system: rec {
      # `nix build`
      packages = (pkgSet system) // {
        # We have to do it like `nix develop .#commit` because libraries don't play well with `makeBinPath` or `makeLibraryPath`.
        commit = (import ./commit.nix {
          lib = utils.lib;
          pkgs = (pkgsWithRust system);
        });
      };

      # TODO: figure out a way to write it as packages.default
      # defaultPackage = packages.dcompass-maxmind;

      # We don't check packages.commit because techinically it is not a pacakge
      checks = builtins.removeAttrs packages [ "commit" ];

      # `nix run`
      apps = {
        update = utils.lib.mkApp {
          drv = with (pkgsWithRust system);
            (writeShellApplication {
              name = "dcompass-update-data";
              runtimeInputs = [ wget gzip ];
              text = ''
                set -e
                wget -O ./data/full.mmdb --show-progress https://github.com/Dreamacro/maxmind-geoip/releases/latest/download/Country.mmdb
                wget -O ./data/cn.mmdb --show-progress https://github.com/Hackl0us/GeoIP2-CN/raw/release/Country.mmdb
                wget -O ./data/ipcn.txt --show-progress https://github.com/17mon/china_ip_list/raw/master/china_ip_list.txt
                gzip -f -k ./data/ipcn.txt
              '';
            });
        };
      } // (forEachFeature (v:
        utils.lib.mkApp {
          drv = packages."dcompass-${strings.removePrefix "geoip-" v}";
        }));

      defaultApp = apps.dcompass-maxmind;

      # `nix develop`
      devShells.default = with (pkgsWithRust system);
        mkShell {
          nativeBuildInputs = lib.flatten [
            # write rustfmt first to ensure we are using nightly rustfmt
            rust-bin.nightly."2022-01-01".rustfmt
            rust-bin.stable.latest.default
            rust-bin.stable.latest.rust-src
            rust-analyzer

            # OpenSSL
            pkg-config
            openssl

            # protobuf

            # use by rust-gdb
            gdb

            binutils-unwrapped
            cargo-cache
            cargo-outdated

            (if stdenv.isLinux then [ linuxPackages.perf ] else [ ])

            # perl
            # gnumake
          ];
        };
    }) // {
      # public key for dcompass.cachix.org
      publicKey =
        "dcompass.cachix.org-1:uajJEJ1U9uy/y260jBIGgDwlyLqfL1sD5yaV/uWVlbk=";

      overlays.default = final: prev: {
        dcompass = recurseIntoAttrs (pkgSet prev.pkgs.system);
      };
    };
}
