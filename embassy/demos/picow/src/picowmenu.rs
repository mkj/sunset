use core::fmt::Write;
use core::future::{poll_fn, Future};
use core::sync::atomic::Ordering::{Relaxed, SeqCst};
use core::ops::DerefMut;


use embassy_sync::waitqueue::MultiWakerRegistration;

use crate::demo_common;
use crate::GlobalState;
use demo_common::{BufOutput, SSHConfig};

use demo_common::menu::*;

pub(crate) struct MenuCtx {
    pub out: BufOutput,
    pub state: &'static GlobalState,

    // flags to be handled by the calling async loop
    pub switch_usb1: bool,
    pub need_save: bool,
}

impl MenuCtx {
    pub fn new(state: &'static GlobalState) -> Self {
        Self { state, out: Default::default(), switch_usb1: false, need_save: false }
    }

    fn with_config<F>(&mut self, f: F) -> bool
        where F: FnOnce(&mut SSHConfig, &mut BufOutput)
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
    entry: Some(enter_top),
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

const WIFI_ITEM: Item<MenuCtx> = Item {
    command: "wifi",
    item_type: ItemType::Menu(&Menu {
        label: "wifi",
        items: &[
            &Item {
                command: "net",
                item_type: ItemType::Callback {
                    parameters: &[
                        Parameter::Mandatory { parameter_name: "ssid", help: None },
                    ],
                    function: do_wifi_net,
                },
                help: None,
            },
            &Item {
                command: "wpa2",
                item_type: ItemType::Callback {
                    parameters: &[
                        Parameter::Mandatory { parameter_name: "password", help: None },
                    ],
                    function: do_wifi_wpa2,
                },
                help: None,
            },
            &Item {
                command: "open",
                item_type: ItemType::Callback {
                    parameters: &[],
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
        items: &[
            &Item {
                command: "usb0",
                item_type: ItemType::Callback {
                    parameters: &[],
                    function: do_usb1,
                },
                help: Some("Connect to if00 serial port. Disconnect to exit."),
            },
        ],
        entry: None,
        exit: None,
    }),
    help: Some("Passwords and Keys."),
};

fn enter_top(context: &mut MenuCtx) {
    writeln!(context, "In setup menu").unwrap();
}

fn enter_auth(context: &mut MenuCtx) {
    writeln!(context, "In auth menu").unwrap();
}

fn do_auth_show(_item: &Item<MenuCtx>, _args: &[&str], context: &mut MenuCtx) {
    writeln!(context, "auth key");
}

fn do_auth_key(_item: &Item<MenuCtx>, _args: &[&str], context: &mut MenuCtx) {
    writeln!(context, "auth key");
}

fn do_auth_pw(_item: &Item<MenuCtx>, _args: &[&str], context: &mut MenuCtx) {
    writeln!(context, "this is auth pw");
}

fn do_gpio_show(_item: &Item<MenuCtx>, _args: &[&str], context: &mut MenuCtx) {
    writeln!(context, "gpio show here");
}

fn do_gpio_set(_item: &Item<MenuCtx>, _args: &[&str], context: &mut MenuCtx) {}

fn do_erase_config(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
}

fn do_reset(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {}

fn do_about(_item: &Item<MenuCtx>, _args: &[&str], context: &mut MenuCtx) {
    let _ = writeln!(context, "Sunset SSH, USB serial\nMatt Johnston <matt@ucc.asn.au>\n");
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

fn do_wifi_net(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    context.with_config(|c, out| {
        let net = args[0];
        if c.wifi_net.capacity() > net.len() {
            writeln!(out, "Too long");
            return;
        }
        c.wifi_net = net.into();
    });
    context.need_save = true;
    wifi_entry(context);
}

fn do_wifi_wpa2(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    context.with_config(|c, out| {
        let pw = args[0];
        if pw.len() > 63 {
            writeln!(out, "Too long");
            return;
        }
        c.wifi_pw = Some(pw.into())
    });
    context.need_save = true;
    wifi_entry(context);
}

fn do_wifi_open(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    context.with_config(|c, out| {
        c.wifi_pw = None;
    });
    context.need_save = true;
    wifi_entry(context);
}
