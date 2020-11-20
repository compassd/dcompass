#!/usr/bin/env bash

find . -type f -name '*.sh' -exec shellcheck {} +
find . -type f -name '*.sh' -exec shfmt -w {} +
find . -type f -name '*.nix' -exec nixfmt {} +
cargo fmt -- --check
cargo build
cargo test
cargo clippy

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
