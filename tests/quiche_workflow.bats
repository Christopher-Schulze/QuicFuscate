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
    ./scripts/quiche_workflow.sh --mirror "file://$repo" --step patch
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
diff --git a/Cargo.toml b/Cargo.toml
index 0000000..1111111 100644
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -1,4 +1,4 @@
 [package]
-name = "quiche"
+name = "quiche_patched"
 version = "0.1.0"
 edition = "2021"
PATCH

    cp -r "$repo" libs/patched_quiche
    ./scripts/quiche_workflow.sh --step patch --step build

    [ -h "libs/patched_quiche/target/latest" ]
}

@test "build.rs triggers workflow" {
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
diff --git a/Cargo.toml b/Cargo.toml
index 0000000..1111111 100644
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -1,4 +1,4 @@
 [package]
-name = "quiche"
+name = "quiche_patched"
 version = "0.1.0"
 edition = "2021"
PATCH
    cp "$BATS_TEST_DIRNAME/../build.rs" build.rs
    mkdir -p src
    echo "pub fn dummy() {}" > src/lib.rs
    cat > Cargo.toml <<'CARGO'
[package]
name = "dummy"
version = "0.1.0"
edition = "2021"
build = "build.rs"
CARGO
    cp -r "$repo" libs/patched_quiche
    MIRROR_URL="file://$repo" cargo build -q
    [ -d "libs/patched_quiche/quiche" ]
}

@test "download patch and build quiche" {
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
diff --git a/Cargo.toml b/Cargo.toml
index 0000000..1111111 100644
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -1,4 +1,4 @@
 [package]
-name = "quiche"
+name = "quiche_patched"
 version = "0.1.0"
 edition = "2021"
PATCH

    run ./scripts/quiche_workflow.sh --mirror "file://$repo" --step fetch --step patch --step build
    [ "$status" -eq 0 ]
    grep -q 'name = "quiche_patched"' libs/patched_quiche/quiche/Cargo.toml
    [ -e "libs/patched_quiche/target/latest" ]
}
