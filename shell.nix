let
  mozilla = import (builtins.fetchTarball https://github.com/mozilla/nixpkgs-mozilla/archive/master.tar.gz);
  nixpkgs = import <nixpkgs> { overlays = [ mozilla ]; };
in
  with nixpkgs;

  mkShell {
    buildInputs = [
      clang # needed for bindgen
      latest.rustChannels.stable.rust
      pkgconfig
    ];
}
