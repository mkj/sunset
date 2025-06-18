#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use sunset::{KeyType, SignKey};

use sunset_fuzz::*;

fn main() {
    let conf =
        server::Config { key: SignKey::generate(KeyType::Ed25519, None).unwrap() };
    run_main(&conf, |_path, ctx, data| server::run(data, ctx))
}
