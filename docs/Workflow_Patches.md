# Quiche Workflow Usage

This document describes how to run the automated workflow and when to create new patches for the embedded quiche library.

## Running the workflow

Execute the helper script to fetch quiche, apply all patches and build the library:

```bash
./scripts/quiche_workflow.sh --type release
```

Specific steps can be called individually:

```bash
./scripts/quiche_workflow.sh --step fetch
./scripts/quiche_workflow.sh --step patch
./scripts/quiche_workflow.sh --step verify_patches
./scripts/quiche_workflow.sh --step build
./scripts/quiche_workflow.sh --step test
```
If the workflow aborts during patching or building consult the log files under `libs/logs/` for details. Often the submodule was not initialised correctly.
Re-run the following command and start the workflow again:

```bash
git submodule update --init libs/patched_quiche
./scripts/quiche_workflow.sh --step fetch
```


After the `fetch` step the submodule `libs/patched_quiche` is fully initialised including its own submodules. The environment variable `QUICHE_PATH` will point to the sources.

## Creating new patches

Whenever the quiche submodule is updated or custom behaviour is added, generate a new patch file:

```bash
cd libs/patched_quiche
# apply your modifications
git add -u
git commit -m "Describe changes"
cd ..
git format-patch -1 HEAD --output-directory ../patches
git -C patched_quiche reset --hard HEAD~1
```

Store the patch under `libs/patches/`. The workflow applies all patches automatically during builds.

## GitHub Actions

The repository provides an automated workflow in `.github/workflows/build-quiche.yml`.
It clones the project with all submodules, runs the helper script for each step
(fetch, patch, verify, build and test) and uploads the resulting artifacts. Run
it manually from the GitHub UI or trigger it on each push.

### When to create new patches

Create a new patch whenever:

- the quiche submodule is updated,
- custom TLS handling or SIMD optimizations change, or
- additional features require modifications to the vendored quiche sources.

Use the procedure above to generate a `.patch` file and store it under
`libs/patches/`.
