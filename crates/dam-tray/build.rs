fn main() {
    #[cfg(target_os = "macos")]
    {
        println!("cargo:rerun-if-changed=native/dam_system_extension_activation.m");
        cc::Build::new()
            .file("native/dam_system_extension_activation.m")
            .flag("-fobjc-arc")
            .flag("-fblocks")
            .flag("-fmodules")
            .compile("dam_tray_system_extension_activation");
        println!("cargo:rustc-link-lib=framework=Foundation");
        println!("cargo:rustc-link-lib=framework=ServiceManagement");
        println!("cargo:rustc-link-lib=framework=SystemExtensions");
    }
}
