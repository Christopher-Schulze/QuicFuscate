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

    # Create a patch that will not apply
    cat > "$proj/libs/patches/bad.patch" <<'PATCH'
--- a/unknown.txt
+++ b/unknown.txt
@@
+broken
PATCH

    cd "$proj"
}

teardown() {
    rm -rf "$tmpdir"
}

@test "fails when patches do not apply" {
    run env MIRROR_URL="file://$repo" ./scripts/quiche_workflow.sh --step patch
    [ "$status" -ne 0 ]
    [[ "$output" == *"git apply --check fehlgeschlagen"* ]]
}

