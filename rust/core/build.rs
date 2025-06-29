fn main() {
    cc::Build::new()
        .cpp(true)
        .file("src/ffi.cpp")
        .include("../../core")
        .flag_if_supported("-std=c++17")
        .compile("coreffi");
}
