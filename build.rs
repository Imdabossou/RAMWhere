fn main() {
    println!("cargo:rerun-if-changed=assets/RAMWhere.rc");
    println!("cargo:rerun-if-changed=assets/RAMWhere.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed_resource::compile("assets/RAMWhere.rc", embed_resource::NONE).manifest_optional().unwrap();
    }
}
