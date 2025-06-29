fn main() {
    cc::Build::new()
        .cpp(true)
        .file("../../stealth/XOR_Obfuscation.cpp")
        .file("src/ffi.cpp")
        .include("../../stealth")
        .flag_if_supported("-std=c++17")
        .compile("stealthffi");
}
