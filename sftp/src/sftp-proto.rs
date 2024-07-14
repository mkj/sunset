#[derive(SSHEncode, SSHDecode)]
struct Init {
    version: u32,
    // TODO extensions
}

#[derive(SSHEncode, SSHDecode)]
struct Version {
    version: u32,
    // TODO extensions
}

struct FileAttrs {
    flags: u32,
    size: u64,
    uid: Option<u32>,
    gid: Option<u32>,
    permissions: Option<u32>,
    atime: Option<u32>,
    mtime: Option<u32>,
    // TODO extended
}

#[derive(SSHEncode, SSHDecode)]
struct Open {
    id: u32,
    // TODO or TextString
    filename: BinString,
    pflags: 32,
    attrs: FileAttrs,
}

#[repr(u32)]
enum Pflags {
    Read = 1,
    Write = 2,
    Append = 4,
    Creat = 8,
    Trunc = 16,
    Excl = 32,
}

#[derive(SSHEncode, SSHDecode)]
struct Close {
    id: u32,
    handle: BinString,
}

#[derive(SSHEncode, SSHDecode)]
struct Read {
    id: u32,
    handle: BinString,
    offset: u64,
    len: u32,
}

#[derive(SSHEncode, SSHDecode)]
struct Write {
    id: u32,
    handle: BinString,
    offset: u64,
    data: BinString,
}

#[derive(SSHEncode, SSHDecode)]
struct Remove {
    id: u32,
    filename: BinString,
}

#[derive(SSHEncode, SSHDecode)]
struct Rename {
    id: u32,
    old: BinString,
    new: BinString,
}

#[derive(SSHEncode, SSHDecode)]
struct Mkdir {
    id: u32,
    path: BinString,
    attrs: FileAttrs,
}


#[derive(SSHEncode, SSHDecode)]
struct Status {
    id: u32,
    status_code: u32,
    msg: TextString,
    lang: &str,
}

#[repr(u32)]
enum StatusCode {
    Ok = 1,
    Eof = 2,
    NoSuchFile = 3,
    PermissionDenied = 4,
    Failure = 5,
    BadMessage = 6,
    NoConnection = 7,
    ConnectionLost = 8,
    OpUnsupported = 9,
}

#[derive(SSHEncode, SSHDecode)]
struct Handle {
    id: u32,
    handle: BinString,
}

#[derive(SSHEncode, SSHDecode)]
struct Data {
    id: u32,
    handle: BinString,
    offset: u64,
    data: BinString,
}

#[derive(SSHEncode, SSHDecode)]
struct Name<'a> {
    id: u32,
    names: &'a [i]
}
