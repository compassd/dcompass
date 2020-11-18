let
  mozilla = import (builtins.fetchTarball
    "https://github.com/mozilla/nixpkgs-mozilla/archive/master.tar.gz");
  nixpkgs = import <nixpkgs> { overlays = [ mozilla ]; };

  stableRust = nixpkgs.latest.rustChannels.stable.rust;
  nightlyRust = (nixpkgs.rustChannelOf {
    date = "2020-11-18";
    channel = "nightly";
  }).rust.override { extensions = [ "rustfmt-preview" ]; };

  rustEnv = nixpkgs.symlinkJoin {
    name = "rust-develop-envrionment";
    paths = [ stableRust ];
    postBuild = ''
      ln -sf ${nightlyRust}/bin/cargo-fmt $out/bin/
      ln -sf ${nightlyRust}/bin/rustfmt $out/bin/
    '';
  };
in with nixpkgs;

mkShell {
  buildInputs = [
    clang # needed for bindgen
    rustEnv
    pkgconfig
  ];
}
