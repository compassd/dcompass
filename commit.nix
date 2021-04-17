{ pkgs, lib }:
with pkgs;
lib.mkApp {
  drv = pkgs.writeShellScriptBin "dcompass-commit" ''
    export PATH=${
      pkgs.lib.strings.makeBinPath [
        shellcheck
        shfmt
        git
        coreutils
        findutils
        nixfmt

        gcc
        # write rustfmt first to ensure we are using nightly rustfmt
        rust-bin.nightly."2021-01-01".rustfmt
        rust-bin.stable.latest.default
        binutils-unwrapped
      ]
    }

    set -e

    find . -type f -name '*.sh' -exec shellcheck {} +
    find . -type f -name '*.sh' -exec shfmt -w {} +
    find . -type f -name '*.nix' -exec nixfmt {} +
    cargo update
    cargo fmt -- --check
    cargo build --all-features
    cargo test
    cargo clippy
    cargo bench --no-run

    echo -n "Adding to git..."
    git add --all
    echo "Done."

    git status
    read -n 1 -s -r -p "Press any key to continue"

    echo "Commiting..."
    echo "Enter commit message: "
    read -r commitMessage
    git commit -m "$commitMessage"
    echo "Done."

    echo -n "Pushing..."
    git push
    echo "Done."

  '';
}
