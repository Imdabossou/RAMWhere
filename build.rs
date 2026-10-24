fn main() {
    println!("cargo:rerun-if-changed=assets/ramwhere.rc");
    println!("cargo:rerun-if-changed=assets/ramwhere.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed_resource::compile("assets/ramwhere.rc", embed_resource::NONE).manifest_optional().unwrap();
    }
}
