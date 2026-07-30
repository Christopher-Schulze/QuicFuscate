fn main() {
    // Avoid Cargo's default "scan the entire package tree" behavior for build script rerun decisions.
    // That scan can fail when dev tools create/remove ephemeral directories during tests.
    println!("cargo:rerun-if-changed=build.rs");
}
