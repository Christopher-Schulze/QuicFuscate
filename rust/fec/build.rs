fn main() {
    cc::Build::new()
        .cpp(true)
        .file("../../fec/FEC_Modul.cpp")
        .include("../../fec")
        .flag_if_supported("-std=c++17")
        .flag_if_supported("-fopenmp")
        .flag_if_supported("-mavx2")
        .compile("fecffi");
}
