#!/usr/bin/env bats

setup() {
    tmpdir=$(mktemp -d)
    repo="$tmpdir/repo"
    mkdir -p "$repo/quiche"
    echo "test" > "$repo/quiche/README.md"
    git init -q "$repo"
    git -C "$repo" add .
    git -C "$repo" commit -q -m "init"

    proj="$tmpdir/project"
    mkdir -p "$proj/scripts"
    cp scripts/quiche_workflow.sh "$proj/scripts/"
    mkdir -p "$proj/libs/patches"

    cd "$proj"
}

teardown() {
    rm -rf "$tmpdir"
}

@test "automatically fetches quiche when missing" {
    MIRROR_URL="file://$repo" ./scripts/quiche_workflow.sh --step patch
    [ -d "libs/patched_quiche/quiche" ]
}


@test "runs full workflow" {
    cat > "$repo/Cargo.toml" <<'CARGO'
[package]
name = "quiche"
version = "0.1.0"
edition = "2021"

[lib]
path = "lib.rs"
CARGO
    echo "pub fn hello() {}" > "$repo/lib.rs"
    git -C "$repo" add Cargo.toml lib.rs
    git -C "$repo" commit -q -m "cargo init"

    cat > "$proj/libs/patches/name.patch" <<'PATCH'
--- a/Cargo.toml
+++ b/Cargo.toml
@@
-name = "quiche"
+name = "quiche_patched"
PATCH

    MIRROR_URL="file://$repo" ./scripts/quiche_workflow.sh

    [ -h "libs/patched_quiche/target/latest" ]
    grep -q "quiche_patched" libs/patched_quiche/Cargo.toml
}
