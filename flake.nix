{
  description = "dcompass project";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { nixpkgs, rust-overlay, ... }: {
    devShell."x86_64-linux" = with import nixpkgs {
      system = "x86_64-linux";
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
  };
}
