fn main() {
    let sunset_ssh_ident = format!("SSH-2.0-Sunset-{}", env!("CARGO_PKG_VERSION"));
    println!("cargo::rustc-env=SUNSET_SSH_IDENT={sunset_ssh_ident}");
}
