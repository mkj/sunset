use core::fmt::Write;
use core::future::{poll_fn, Future};
use core::ops::DerefMut;
use core::sync::atomic::Ordering::{Relaxed, SeqCst};

use embedded_io::asynch;
use embedded_io::asynch::Write as _;

use embassy_sync::waitqueue::MultiWakerRegistration;

use heapless::{String, Vec};

use crate::demo_common;
use crate::GlobalState;
use demo_common::{BufOutput, SSHConfig};

use demo_common::menu::*;

use sunset::packets::Ed25519PubKey;

// arbitrary in bytes, for sizing buffers
const MAX_PW_LEN: usize = 50;

pub(crate) struct MenuCtx {
    pub out: BufOutput,
    pub state: &'static GlobalState,

    // flags to be handled by the calling async loop
    pub switch_usb1: bool,
    pub need_save: bool,

    pub logout: bool,
    pub reset: bool,
}

impl MenuCtx {
    pub fn new(state: &'static GlobalState) -> Self {
        Self {
            state,
            out: Default::default(),
            switch_usb1: false,
            need_save: false,
            logout: false,
            reset: false,
        }
    }

    fn with_config<F>(&mut self, f: F) -> bool
    where
        F: FnOnce(&mut SSHConfig, &mut BufOutput),
    {
        let mut c = match self.state.config.try_lock() {
            Ok(c) => c,
            Err(e) => {
                writeln!(self, "Lock problem, try again.");
                return false;
            }
        };
        f(c.deref_mut(), &mut self.out);
        true
    }
}

impl core::fmt::Write for MenuCtx {
    fn write_str(&mut self, s: &str) -> Result<(), core::fmt::Error> {
        self.out.write_str(s)
    }
}

pub(crate) const SETUP_MENU: Menu<MenuCtx> = Menu {
    label: "setup",
    items: &[
        &Item {
            command: "logout",
            help: None,
            item_type: ItemType::Callback { function: do_logout, parameters: &[] },
        },
        &AUTH_ITEM,
        &GPIO_ITEM,
        &SERIAL_ITEM,
        &WIFI_ITEM,
        &Item {
            command: "reset",
            help: Some("Reset picow. Will log out."),
            item_type: ItemType::Callback { function: do_reset, parameters: &[] },
        },
        &Item {
            command: "erase_config",
            item_type: ItemType::Callback {
                function: do_erase_config,
                parameters: &[Parameter::Optional {
                    parameter_name: "",
                    help: None,
                }],
            },
            help: Some("Erase all config."),
        },
        &Item {
            command: "about",
            item_type: ItemType::Callback { function: do_about, parameters: &[] },
            help: None,
        },
    ],
    entry: None,
    exit: None,
};

const AUTH_ITEM: Item<MenuCtx> = Item {
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
                command: "console-noauth",
                item_type: ItemType::Callback {
                    parameters: &[Parameter::Mandatory {
                        parameter_name: "yesno",
                        help: Some("Set yes for SSH to serial with no auth. Take care!"),
                    }],
                    function: do_console_noauth,
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
                    function: do_key,
                },
                help: None,
            },
            &Item {
                command: "clear-key",
                item_type: ItemType::Callback {
                    parameters: &[Parameter::Mandatory {
                        parameter_name: "slot",
                        help: None,
                    }],
                    function: do_clear_key,
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
                    function: do_console_pw,
                },
                help: None,
            },
            &Item {
                command: "disable-password",
                item_type: ItemType::Callback {
                    parameters: &[],
                    function: do_console_clear_pw,
                },
                help: None,
            },
            &Item {
                command: "admin-key",
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
                    function: do_admin_key,
                },
                help: None,
            },
            &Item {
                command: "clear-admin-key",
                item_type: ItemType::Callback {
                    parameters: &[Parameter::Mandatory {
                        parameter_name: "slot",
                        help: None,
                    }],
                    function: do_admin_clear_key,
                },
                help: None,
            },
            &Item {
                command: "admin-password",
                item_type: ItemType::Callback {
                    parameters: &[Parameter::Mandatory {
                        parameter_name: "pw",
                        help: None,
                    }],
                    function: do_admin_pw,
                },
                help: Some("Password for serial or config@. 'None' to clear"),
            },
            &Item {
                command: "clear-admin-password",
                item_type: ItemType::Callback {
                    parameters: &[],
                    function: do_admin_clear_pw,
                },
                help: None,
            },
        ],
        entry: Some(enter_auth),
        exit: None,
    }),
    help: Some("Passwords and Keys."),
};

const WIFI_ITEM: Item<MenuCtx> = Item {
    command: "wifi",
    item_type: ItemType::Menu(&Menu {
        label: "wifi",
        items: &[
            &Item {
                command: "wpa2",
                item_type: ItemType::Callback {
                    parameters: &[
                        Parameter::Mandatory {
                            parameter_name: "net",
                            help: Some("ssid"),
                        },
                        Parameter::Mandatory {
                            parameter_name: "password",
                            help: None,
                        },
                    ],
                    function: do_wifi_wpa2,
                },
                help: None,
            },
            &Item {
                command: "open",
                item_type: ItemType::Callback {
                    parameters: &[Parameter::Mandatory {
                        parameter_name: "net",
                        help: Some("ssid"),
                    }],
                    function: do_wifi_open,
                },
                help: None,
            },
        ],
        entry: Some(wifi_entry),
        exit: None,
    }),
    help: None,
};

const GPIO_ITEM: Item<MenuCtx> = Item {
    command: "gpio",
    item_type: ItemType::Menu(&Menu {
        label: "gpio",
        items: &[
            &Item {
                command: "show",
                item_type: ItemType::Callback {
                    parameters: &[],
                    function: do_gpio_show,
                },
                help: None,
            },
            &Item {
                command: "set",
                item_type: ItemType::Callback {
                    parameters: &[
                        Parameter::Mandatory { parameter_name: "pin", help: None },
                        Parameter::Mandatory {
                            parameter_name: "state",
                            help: Some("0/1/Z"),
                        },
                    ],
                    function: do_gpio_set,
                },
                help: None,
            },
        ],
        entry: None,
        exit: None,
    }),
    help: Some("GPIO, todo"),
};

const SERIAL_ITEM: Item<MenuCtx> = Item {
    command: "serial",
    item_type: ItemType::Menu(&Menu {
        label: "serial",
        items: &[&Item {
            command: "usb0",
            item_type: ItemType::Callback { parameters: &[], function: do_usb1 },
            help: Some("Connect to if00 serial port. Disconnect to exit."),
        }],
        entry: None,
        exit: None,
    }),
    help: Some("Passwords and Keys."),
};

fn enter_auth(context: &mut MenuCtx) {
    writeln!(context, "In auth menu").unwrap();
}

fn endis(v: bool) -> &'static str {
    if v {
        "enabled"
    } else {
        "disabled"
    }
}

fn prkey(context: &mut dyn Write, name: &str, k: &Option<Ed25519PubKey>) {
    if let Some(k) = k {
        writeln!(context, "{} ed25519 todo", name);
    } else {
        writeln!(context, "{} disabled", name);
    }
}

fn do_auth_show(_item: &Item<MenuCtx>, _args: &[&str], context: &mut MenuCtx) {
    context.with_config(|c, out| {
        write!(out, "Console password ");
        if c.console_noauth {
            writeln!(out, "not required");
        } else {
            writeln!(out, "{}", endis(c.console_pw.is_some()));
        }
        writeln!(out, "Console password {}", endis(c.console_pw.is_some()));
        prkey(out, "Console key1", &c.console_keys[0]);
        prkey(out, "Console key2", &c.console_keys[1]);
        prkey(out, "Console key3", &c.console_keys[2]);
        writeln!(out, "Admin password {}", endis(c.admin_pw.is_some()));
        prkey(out, "Admin key1", &c.admin_keys[0]);
        prkey(out, "Admin key2", &c.admin_keys[1]);
        prkey(out, "Admin key3", &c.admin_keys[2]);
    });
}

fn do_key(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    let slot: usize = match args[0].parse() {
        Err(e) => {
            writeln!(context, "Bad slot");
            return;
        }
        Ok(s) => s,
    };
    if slot == 0 || slot > demo_common::config::KEY_SLOTS {
        writeln!(context, "Bad slot");
        return;
    }
    context.need_save = true;

    writeln!(context, "todo openssh key parsing");
}

fn do_clear_key(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    writeln!(context, "todo");
    context.need_save = true;
}

fn do_console_pw(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    let pw = args[0];
    if pw.as_bytes().len() > MAX_PW_LEN {
        writeln!(context, "Too long");
        return;
    }
    context.with_config(|c, out| {
        match c.set_console_pw(Some(pw)) {
            Ok(()) => writeln!(out, "Set console password"),
            Err(e) => writeln!(out, "Failed setting, {}", e),
        };
    });
    context.need_save = true;
}

// TODO: this is a bit hazardous with the takepipe kickoff mechanism
fn do_console_noauth(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    context.with_config(|c, out| {
        c.console_noauth = args[0] == "yes";
        let _ = writeln!(out, "Set console noauth {}", if c.console_noauth {
            "yes"
        } else {
            "no"
        });
    });
    context.need_save = true;
}

fn do_admin_key(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    writeln!(context, "todo");
    context.need_save = true;
}

fn do_admin_clear_key(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    writeln!(context, "todo");
    context.need_save = true;
}

fn do_console_clear_pw(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    context.with_config(|c, out| {
        let _ = c.set_console_pw(None);
        writeln!(out, "Disabled console password");
    });
    context.need_save = true;
}

fn do_admin_pw(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    let pw = args[0];
    if pw.as_bytes().len() > MAX_PW_LEN {
        writeln!(context, "Too long");
        return;
    }
    context.with_config(|c, out| {
        match c.set_admin_pw(Some(pw)) {
            Ok(()) => writeln!(out, "Set admin password"),
            Err(e) => writeln!(out, "Failed setting, {}", e),
        };
    });
    context.need_save = true;
}

fn do_admin_clear_pw(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    context.with_config(|c, out| {
        let _ = c.set_admin_pw(None);
        writeln!(out, "Disabled admin password");
    });
    context.need_save = true;
}

fn do_gpio_show(_item: &Item<MenuCtx>, _args: &[&str], context: &mut MenuCtx) {
    writeln!(context, "gpio show here");
}

fn do_gpio_set(_item: &Item<MenuCtx>, _args: &[&str], context: &mut MenuCtx) {}

fn do_erase_config(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {}

fn do_logout(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    context.logout = true;
}

fn do_reset(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    context.reset = true;
}

fn do_about(_item: &Item<MenuCtx>, _args: &[&str], context: &mut MenuCtx) {
    let _ = writeln!(
        context,
        "Sunset SSH, USB serial\nMatt Johnston <matt@ucc.asn.au>\n"
    );
}

fn do_usb1(_item: &Item<MenuCtx>, _args: &[&str], context: &mut MenuCtx) {
    writeln!(context, "USB serial");
    context.switch_usb1 = true;
}

fn wifi_entry(context: &mut MenuCtx) {
    context.with_config(|c, out| {
        write!(out, "Wifi net {} ", c.wifi_net);
        if c.wifi_pw.is_some() {
            writeln!(out, "wpa2");
        } else {
            writeln!(out, "open");
        }
    });
}

fn do_wifi_wpa2(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    context.with_config(|c, out| {
        let net = args[0];
        let pw = args[1];
        if c.wifi_net.capacity() < net.len() {
            writeln!(out, "Too long net");
            return;
        }
        if pw.len() > 63 {
            writeln!(out, "Too long pw");
            return;
        }
        c.wifi_net = net.into();
        c.wifi_pw = Some(pw.into())
    });
    context.need_save = true;
    wifi_entry(context);
}

fn do_wifi_open(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    context.with_config(|c, out| {
        let net = args[0];
        if c.wifi_net.capacity() < net.len() {
            writeln!(out, "Too long net");
            return;
        }
        c.wifi_pw = None;
    });
    context.need_save = true;
    wifi_entry(context);
}

// Returns an error on EOF etc.
pub(crate) async fn request_pw<E>(
    tx: &mut impl asynch::Write<Error = E>,
    rx: &mut impl asynch::Read<Error = E>,
) -> Result<String<MAX_PW_LEN>, ()> {
    tx.write_all(b"\r\nEnter Password: ").await.map_err(|_| ())?;
    let mut pw = Vec::<u8, MAX_PW_LEN>::new();
    loop {
        let mut c = [0u8];
        rx.read_exact(&mut c).await.map_err(|_| ())?;
        let c = c[0];
        if c == b'\r' || c == b'\n' {
            break;
        }
        pw.push(c).map_err(|_| ())?;
    }

    let pw = core::str::from_utf8(&pw).map_err(|_| ())?;
    return Ok(pw.into());
}
