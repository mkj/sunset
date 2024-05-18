// callbacks have lots of unused arguments. Ignore them, this might get replaced.
#![allow(unused)]

#[allow(unused_imports)]
pub use log::{debug, error, info, log, trace, warn};

use core::fmt::{Write as _, Debug, Display};
use core::future::{poll_fn, Future};
use core::ops::{DerefMut, ControlFlow};
use core::sync::atomic::Ordering::{Relaxed, SeqCst};
use core::str::FromStr;

use embedded_io_async::{Write as AsyncWrite, Read as AsyncRead, ErrorType};

use embassy_sync::waitqueue::MultiWakerRegistration;
use embassy_time::Duration;
use embassy_net::{Ipv4Cidr, Ipv4Address};

use heapless::{String, Vec};

use pretty_hex::PrettyHex;

use crate::demo_common;
use crate::flashconfig;
use crate::GlobalState;
use demo_common::{BufOutput, SSHConfig};

use demo_common::menu::*;

use sunset::packets::Ed25519PubKey;
use sunset::*;

// arbitrary in bytes, for sizing buffers
const MAX_PW_LEN: usize = 50;

pub(crate) struct MenuCtx {
    pub out: BufOutput,
    state: &'static GlobalState,

    // true for local serial console menu, false for SSH menu
    local: bool,

    // flags to be handled by progress() called from the async loop
    switch_usb1: bool,
    switch_serial1: bool,
    need_save: bool,
    logout: bool,
    reset: bool,
    bootsel: bool,
}

impl MenuCtx {
    pub fn new(state: &'static GlobalState, local: bool) -> Self {
        Self {
            state,
            local,
            out: Default::default(),
            switch_usb1: false,
            switch_serial1: false,
            need_save: false,
            logout: false,
            reset: false,
            bootsel: false,
        }
    }

    /// Calls a closure with the config.
    ///
    /// Any modifications will be saved to flash (on a future `progress()` call).
    fn with_config<F>(&mut self, f: F) -> bool
    where
        F: FnOnce(&mut SSHConfig, &mut BufOutput),
    {
        let mut c = match self.state.config.try_lock() {
            Ok(c) => c,
            Err(e) => {
                let _ = writeln!(self, "Lock problem, try again.");
                return false;
            }
        };
        let prev_config = c.clone();
        f(c.deref_mut(), &mut self.out);
        // test whether config was modified
        if *c != prev_config {
            self.need_save = true
        }
        true
    }

    // Returns `Ok(Break)` to exit the menu
    pub(crate) async fn progress<R, W>(
        &mut self,
        mut chanr: &mut R,
        mut chanw: &mut W,
    ) -> Result<ControlFlow<()>>
    where
        R: AsyncRead<Error = sunset::Error>,
        W: AsyncWrite<Error = sunset::Error>,
    {
        if self.switch_usb1 {
            self.switch_usb1 = false;
            if self.local {
                let _ = writeln!(self.out, "serial can't loop");
            } else {
                if self.state.usb_pipe.is_in_use() {
                    let _ = writeln!(
                        self.out,
                        "Opening usb1, stealing existing session"
                    );
                } else {
                    let _ = writeln!(self.out, "Opening usb1");
                }
                crate::serial(chanr, chanw, self.state.usb_pipe).await?;
                // TODO we could return to the menu on serial error?
                return Ok(ControlFlow::Break(()));
            }
        }

        if self.switch_serial1 {
            self.switch_serial1 = false;
            if self.local {
                let _ = writeln!(self.out, "serial can't loop");
            } else {
                if self.state.serial1_pipe.is_in_use() {
                    let _ = writeln!(
                        self.out,
                        "Opening serial1, stealing existing session"
                    );
                } else {
                    let _ = writeln!(self.out, "Opening serial1");
                }
                crate::serial(chanr, chanw, self.state.serial1_pipe).await?;
                // TODO we could return to the menu on serial error?
                return Ok(ControlFlow::Break(()));
            }
        }

        if self.need_save {
            info!("needs save");
            // clear regardless of success, don't want a tight loop.
            self.need_save = false;

            let conf = self.state.config.lock().await;
            let mut fl = self.state.flash.lock().await;
            if let Err(_e) = flashconfig::save(&mut fl, &conf).await {
                warn!("Error writing flash");
            }
        }

        if self.logout {
            return Ok(ControlFlow::Break(()));
        }

        if self.reset {
            let _ = chanw.write_all(b"Resetting\r\n").await;
            let mut wd = self.state.watchdog.lock().await;
            wd.start(Duration::from_millis(200));
            loop {
                embassy_time::Timer::after(Duration::from_secs(1)).await;
            }
        }

        if self.bootsel {
            embassy_rp::rom_data::reset_to_usb_boot::ptr()(0, 0);
        }

        // write messages from handling
        self.out.flush(&mut chanw).await?;
        Ok(ControlFlow::Continue(()))
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
        // &GPIO_ITEM,
        &SERIAL_ITEM,
        &WIFI_ITEM,
        &NET_ITEM,
        &Item {
            command: "reset",
            help: Some("Reset picow. Will log out."),
            item_type: ItemType::Callback { function: do_reset, parameters: &[] },
        },
        &Item {
            command: "bootsel",
            help: Some("Resets in rp2040 bootsel mode, use with picotool"),
            item_type: ItemType::Callback { function: do_bootsel, parameters: &[] },
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
                        help: Some(
                            "Set yes for SSH to serial with no auth. Take care!",
                        ),
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

const NET_ITEM: Item<MenuCtx> = Item {
    command: "net",
    item_type: ItemType::Menu(&Menu {
        label: "net",
        items: &[
            &Item {
                command: "info",
                item_type: ItemType::Callback {
                    parameters: &[],
                    function: do_net_info,
                },
                help: None,
            },
            &Item {
                command: "dhcp",
                item_type: ItemType::Callback {
                    parameters: &[],
                    function: do_net_dhcp,
                },
                help: None,
            },
            &Item {
                command: "static",
                item_type: ItemType::Callback {
                    parameters: &[
                        Parameter::Mandatory {
                            parameter_name: "address/netmask",
                            help: None,
                        },
                        Parameter::Optional {
                            parameter_name: "gateway",
                            help: None,
                        },
                    ],

                    function: do_net_static,
                },
                help: None,
            },
        ],
        entry: None,
        exit: None,
    }),
    help: None,
};

// const _GPIO_ITEM: Item<MenuCtx> = Item {
//     command: "gpio",
//     item_type: ItemType::Menu(&Menu {
//         label: "gpio",
//         items: &[
//             &Item {
//                 command: "show",
//                 item_type: ItemType::Callback {
//                     parameters: &[],
//                     function: do_gpio_show,
//                 },
//                 help: None,
//             },
//             &Item {
//                 command: "set",
//                 item_type: ItemType::Callback {
//                     parameters: &[
//                         Parameter::Mandatory { parameter_name: "pin", help: None },
//                         Parameter::Mandatory {
//                             parameter_name: "state",
//                             help: Some("0/1/Z"),
//                         },
//                     ],
//                     function: do_gpio_set,
//                 },
//                 help: None,
//             },
//         ],
//         entry: None,
//         exit: None,
//     }),
//     help: Some("GPIO, todo"),
// };

const SERIAL_ITEM: Item<MenuCtx> = Item {
    command: "serial",
    item_type: ItemType::Menu(&Menu {
        label: "serial",
        items: &[
            &Item {
                command: "usb0",
                item_type: ItemType::Callback { parameters: &[], function: do_usb1 },
                help: Some("Connect to if00 serial port. Disconnect to exit."),
            },
            &Item {
                command: "serial1",
                item_type: ItemType::Callback {
                    parameters: &[],
                    function: do_serial1,
                },
                help: Some("Connect to uart0 serial port. Disconnect to exit."),
            },
        ],
        entry: None,
        exit: None,
    }),
    help: Some("Passwords and Keys."),
};

fn enter_auth(context: &mut MenuCtx) {
    let _ = writeln!(context, "In auth menu").unwrap();
}

fn endis(v: bool) -> &'static str {
    if v {
        "enabled"
    } else {
        "disabled"
    }
}

fn prkey(context: &mut dyn core::fmt::Write, name: &str, k: &Option<Ed25519PubKey>) {
    if let Some(k) = k {
        let _ = writeln!(context, "{} ed25519 todo", name);
    } else {
        let _ = writeln!(context, "{} disabled", name);
    }
}

fn do_auth_show(_item: &Item<MenuCtx>, _args: &[&str], context: &mut MenuCtx) {
    context.with_config(|c, out| {
        let _ = write!(out, "Console password ");
        if c.console_noauth {
            let _ = writeln!(out, "not required");
        } else {
            let _ = writeln!(out, "{}", endis(c.console_pw.is_some()));
        }
        let _ = writeln!(out, "Console password {}", endis(c.console_pw.is_some()));
        prkey(out, "Console key1", &c.console_keys[0]);
        prkey(out, "Console key2", &c.console_keys[1]);
        prkey(out, "Console key3", &c.console_keys[2]);
        let _ = writeln!(out, "Admin password {}", endis(c.admin_pw.is_some()));
        prkey(out, "Admin key1", &c.admin_keys[0]);
        prkey(out, "Admin key2", &c.admin_keys[1]);
        prkey(out, "Admin key3", &c.admin_keys[2]);
    });
}

fn do_key(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    let slot: usize = match args[0].parse() {
        Err(e) => {
            let _ = writeln!(context, "Bad slot");
            return;
        }
        Ok(s) => s,
    };
    if slot == 0 || slot > demo_common::config::KEY_SLOTS {
        let _ = writeln!(context, "Bad slot");
        return;
    }

    let _ = writeln!(context, "todo openssh key parsing");
}

fn do_clear_key(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    let _ = writeln!(context, "todo");
}

fn do_console_pw(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    let pw = args[0];
    if pw.as_bytes().len() > MAX_PW_LEN {
        let _ = writeln!(context, "Too long");
        return;
    }
    context.with_config(|c, out| {
        let _ = match c.set_console_pw(Some(pw)) {
            Ok(()) => writeln!(out, "Set console password"),
            Err(e) => writeln!(out, "Failed setting, {}", e),
        };
    });
}

// TODO: this is a bit hazardous with the takepipe kickoff mechanism
fn do_console_noauth(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    context.with_config(|c, out| {
        c.console_noauth = args[0] == "yes";
        let _ = writeln!(
            out,
            "Set console noauth {}",
            if c.console_noauth { "yes" } else { "no" }
        );
    });
}

fn do_admin_key(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    let _ = writeln!(context, "todo");
}

fn do_admin_clear_key(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    let _ = writeln!(context, "todo");
}

fn do_console_clear_pw(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    context.with_config(|c, out| {
        let _ = c.set_console_pw(None);
        let _ = writeln!(out, "Disabled console password");
    });
}

fn do_admin_pw(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    let pw = args[0];
    if pw.as_bytes().len() > MAX_PW_LEN {
        let _ = writeln!(context, "Too long");
        return;
    }
    context.with_config(|c, out| {
        let _ = match c.set_admin_pw(Some(pw)) {
            Ok(()) => writeln!(out, "Set admin password"),
            Err(e) => writeln!(out, "Failed setting, {}", e),
        };
    });
}

fn do_admin_clear_pw(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    context.with_config(|c, out| {
        let _ = c.set_admin_pw(None);
        let _ = writeln!(out, "Disabled admin password");
    });
}

// fn do_gpio_show(_item: &Item<MenuCtx>, _args: &[&str], context: &mut MenuCtx) {
//     let _ = writeln!(context, "gpio show here");
// }

// fn do_gpio_set(_item: &Item<MenuCtx>, _args: &[&str], _context: &mut MenuCtx) {}

fn do_erase_config(_item: &Item<MenuCtx>, _args: &[&str], context: &mut MenuCtx) {
    context.with_config(|c, out| match SSHConfig::new() {
        Ok(n) => *c = n,
        Err(e) => {
            let _ = writeln!(out, "failed: {e}");
        }
    });
}

fn do_logout(_item: &Item<MenuCtx>, _args: &[&str], context: &mut MenuCtx) {
    context.logout = true;
}

fn do_reset(_item: &Item<MenuCtx>, _args: &[&str], context: &mut MenuCtx) {
    context.reset = true;
}

fn do_bootsel(_item: &Item<MenuCtx>, _args: &[&str], context: &mut MenuCtx) {
    context.bootsel = true;
}

fn do_about(_item: &Item<MenuCtx>, _args: &[&str], context: &mut MenuCtx) {
    let _ = writeln!(
        context,
        "Sunset SSH, USB serial\nMatt Johnston <matt@ucc.asn.au>\n{}",
        env!("GIT_REV"),
    );
}

fn do_usb1(_item: &Item<MenuCtx>, _args: &[&str], context: &mut MenuCtx) {
    let _ = writeln!(context, "USB serial");
    context.switch_usb1 = true;
}

fn do_serial1(_item: &Item<MenuCtx>, _args: &[&str], context: &mut MenuCtx) {
    let _ = writeln!(context, "serial1");
    context.switch_serial1 = true;
}

fn wifi_entry(context: &mut MenuCtx) {
    context.with_config(|c, out| {
        let _ = write!(out, "Wifi net {} ", c.wifi_net);
        if c.wifi_pw.is_some() {
            let _ = writeln!(out, "wpa2");
        } else {
            let _ = writeln!(out, "open");
        }
    });
}

fn do_wifi_wpa2(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    context.with_config(|c, out| {
        let net = args[0];
        let pw = args[1];
        if c.wifi_net.capacity() < net.len() {
            let _ = writeln!(out, "Too long net");
            return;
        }
        if pw.len() > 63 {
            let _ = writeln!(out, "Too long pw");
            return;
        }
        // OK unwrap, checked length
        c.wifi_net = net.try_into().unwrap();
        // OK unwrap, checked length
        c.wifi_pw = Some(pw.try_into().unwrap())
    });
    wifi_entry(context);
}

fn do_wifi_open(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    context.with_config(|c, out| {
        let net = args[0];
        if c.wifi_net.capacity() < net.len() {
            let _ = writeln!(out, "Too long net");
            return;
        }
        c.wifi_pw = None;
    });
    wifi_entry(context);
}

struct Mac([u8; 6]);

impl Display for Mac {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5])
    }
}

fn do_net_info(_item: &Item<MenuCtx>, _args: &[&str], context: &mut MenuCtx) {
    #[cfg(feature = "w5500")]
    let _ = writeln!(context.out, "w5500 wired ethernet");
    #[cfg(feature = "cyw43")]
    let _ = writeln!(context.out, "cyw43 wifi");
    let _ = writeln!(context.out, "mac address {}", Mac(context.state.net_mac));

    context.with_config(|c, out| {
        if let Some(ref stat) = c.ip4_static {
            let _ = writeln!(out, "static ip4 {stat:?}");
        } else {
            // TODO the actual address
            let _ = writeln!(out, "Using dhcp");
        }
    });
}

fn do_net_dhcp(_item: &Item<MenuCtx>, _args: &[&str], context: &mut MenuCtx) {
    context.with_config(|c, out| {
        c.ip4_static = None;
    });
}

fn do_net_static(_item: &Item<MenuCtx>, args: &[&str], context: &mut MenuCtx) {
    context.with_config(|c, out| {
        let ip = Ipv4Cidr::from_str(args[0]);
        let gw = if args[1].is_empty() {
            Ok(None)
        } else {
            Some(Ipv4Address::from_str(args[1])).transpose()
        };
        match (ip, gw) {
            (Ok(address), Ok(gateway)) => {
                c.ip4_static = Some(embassy_net::StaticConfigV4 {
                    address,
                    gateway,
                    dns_servers: Vec::new(),
                })
            }
            _ => {
                let _ = write!(out, "Bad args");
            }
        }
    });
}

// Returns an error on EOF etc.
pub(crate) async fn request_pw<E>(
    tx: &mut impl AsyncWrite<Error = E>,
    rx: &mut impl AsyncRead<Error = E>,
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
    pw.try_into().map_err(|_| ())
}
