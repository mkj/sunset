use core::fmt::Write;
use demo_common::menu::*;
pub use demo_common::AsyncMenuBuf;
pub(crate) use sunset_demo_embassy_common as demo_common;

/*

config
    auth serial
    auth admin
        password
        key

*/

pub const SETUP_MENU: Menu<AsyncMenuBuf> = Menu {
    label: "setup",
    items: &[
        &AUTH_ITEM,
        &Item {
            item_type: ItemType::Callback {
                function: do_erase_config,
                parameters: &[Parameter::Optional {
                    parameter_name: "",
                    help: None,
                }],
            },
            command: "erase_config",
            help: Some("Erase all config."),
        },
        &Item {
            command: "about",
            item_type: ItemType::Callback { function: do_about, parameters: &[] },
            help: None,
        },
    ],
    entry: Some(enter_top),
    exit: None,
};

const AUTH_ITEM: Item<AsyncMenuBuf> = Item {
    command: "auth",
    item_type: ItemType::Menu(&Menu {
        label: "auth",
        items: &[
            &Item {
                command: "show",
                item_type: ItemType::Callback {
                    parameters: &[],
                    function: do_auth_show,
                },
                help: None,
            },
            &Item {
                command: "key",
                item_type: ItemType::Callback {
                    parameters: &[
                        Parameter::Mandatory { parameter_name: "slot", help: None },
                        Parameter::Mandatory {
                            parameter_name: "ssh-ed25519",
                            help: None,
                        },
                        Parameter::Mandatory {
                            parameter_name: "base64",
                            help: None,
                        },
                        Parameter::Optional {
                            parameter_name: "comment",
                            help: None,
                        },
                    ],
                    // help: Some(
                    //     "An OpenSSH style ed25519 key, eg
                    //     key ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AA...",
                    // ),
                    function: do_auth_key,
                },
                help: None,
            },
            &Item {
                command: "password",
                item_type: ItemType::Callback {
                    parameters: &[Parameter::Mandatory {
                        parameter_name: "pw",
                        help: None,
                    }],
                    function: do_auth_pw,
                },
                help: None,
            },
        ],
        entry: Some(enter_auth),
        exit: None,
    }),
    help: Some("Passwords and Keys."),
};

fn enter_top(context: &mut AsyncMenuBuf) {
    let _ = writeln!(context, "In setup menu").unwrap();
}

fn enter_auth(context: &mut AsyncMenuBuf) {
    let _ = writeln!(context, "In auth menu").unwrap();
}

fn do_auth_show(
    _item: &Item<AsyncMenuBuf>,
    _args: &[&str],
    context: &mut AsyncMenuBuf,
) {
    let _ = writeln!(context, "auth key");
}

fn do_auth_key(
    _item: &Item<AsyncMenuBuf>,
    _args: &[&str],
    context: &mut AsyncMenuBuf,
) {
    let _ = writeln!(context, "auth key");
}

fn do_auth_pw(
    _item: &Item<AsyncMenuBuf>,
    _args: &[&str],
    context: &mut AsyncMenuBuf,
) {
    let _ = writeln!(context, "this is auth pw");
}

fn do_erase_config(
    _item: &Item<AsyncMenuBuf>,
    _args: &[&str],
    _context: &mut AsyncMenuBuf,
) {
}

fn do_about(_item: &Item<AsyncMenuBuf>, _args: &[&str], context: &mut AsyncMenuBuf) {
    let _ = writeln!(
        context,
        "Sunset SSH, USB serial\nMatt Johnston <matt@ucc.asn.au>\n"
    );
}
