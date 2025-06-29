fn main() {
    cc::Build::new()
        .cpp(true)
        .file("../../crypto/morus.cpp")
        .file("src/ffi.cpp")
        .include("../../crypto")
        .flag_if_supported("-std=c++17")
        .compile("cryptoffi");
}
