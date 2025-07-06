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

