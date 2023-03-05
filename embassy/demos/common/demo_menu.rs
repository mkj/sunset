use sunset::Result;

use embedded_io::asynch;

use menu::*;
use core::fmt::Write;

#[derive(Default)]
pub struct Output {
    s: heapless::String<1024>,
}

impl Output {
    pub async fn flush<W>(&mut self, w: &mut W) -> Result<()>
    where W: asynch::Write + embedded_io::Io<Error = sunset::Error>
    {

        let mut b = self.s.as_str().as_bytes();
        while b.len() > 0 {
            let l = w.write(b).await?;
            b = &b[l..];
        }
        self.s.clear();
        Ok(())
    }
}

impl core::fmt::Write for Output {
    fn write_str(&mut self, s: &str) -> Result<(), core::fmt::Error> {
        for c in s.chars() {
            if c == '\n' {
                self.s.push('\r').map_err(|_| core::fmt::Error)?;
            }
            self.s.push(c).map_err(|_| core::fmt::Error)?;
        }
        Ok(())
    }
}

// from menu crate examples/simple.rs

pub const ROOT_MENU: Menu<Output> = Menu {
    label: "root",
    items: &[
        &Item {
            item_type: ItemType::Callback {
                function: select_foo,
                parameters: &[
                    Parameter::Mandatory {
                        parameter_name: "a",
                        help: Some("This is the help text for 'a'"),
                    },
                    Parameter::Optional {
                        parameter_name: "b",
                        help: None,
                    },
                    Parameter::Named {
                        parameter_name: "verbose",
                        help: None,
                    },
                    Parameter::NamedValue {
                        parameter_name: "level",
                        argument_name: "INT",
                        help: Some("Set the level of the dangle"),
                    },
                ],
            },
            command: "foo",
            help: Some(
                "Makes a foo appear.

This is some extensive help text.

It contains multiple paragraphs and should be preceeded by the parameter list.
",
            ),
        },
        &Item {
            item_type: ItemType::Callback {
                function: select_bar,
                parameters: &[],
            },
            command: "bar",
            help: Some("fandoggles a bar"),
        },
        &Item {
            item_type: ItemType::Menu(&Menu {
                label: "sub",
                items: &[
                    &Item {
                        item_type: ItemType::Callback {
                            function: select_baz,
                            parameters: &[],
                        },
                        command: "baz",
                        help: Some("thingamobob a baz"),
                    },
                    &Item {
                        item_type: ItemType::Callback {
                            function: select_quux,
                            parameters: &[],
                        },
                        command: "quux",
                        help: Some("maximum quux"),
                    },
                ],
                entry: Some(enter_sub),
                exit: Some(exit_sub),
            }),
            command: "sub",
            help: Some("enter sub-menu"),
        },
    ],
    entry: Some(enter_root),
    exit: Some(exit_root),
};

fn enter_root(_menu: &Menu<Output>, context: &mut Output) {
    writeln!(context, "In enter_root").unwrap();
}

fn exit_root(_menu: &Menu<Output>, context: &mut Output) {
    writeln!(context, "In exit_root").unwrap();
}

fn select_foo<'a>(_menu: &Menu<Output>, item: &Item<Output>, args: &[&str], context: &mut Output) {
    writeln!(context, "In select_foo. Args = {:?}", args).unwrap();
    writeln!(
        context,
        "a = {:?}",
        ::menu::argument_finder(item, args, "a")
    )
    .unwrap();
    writeln!(
        context,
        "b = {:?}",
        ::menu::argument_finder(item, args, "b")
    )
    .unwrap();
    writeln!(
        context,
        "verbose = {:?}",
        ::menu::argument_finder(item, args, "verbose")
    )
    .unwrap();
    writeln!(
        context,
        "level = {:?}",
        ::menu::argument_finder(item, args, "level")
    )
    .unwrap();
    writeln!(
        context,
        "no_such_arg = {:?}",
        ::menu::argument_finder(item, args, "no_such_arg")
    )
    .unwrap();
}

fn select_bar<'a>(_menu: &Menu<Output>, _item: &Item<Output>, args: &[&str], context: &mut Output) {
    writeln!(context, "In select_bar. Args = {:?}", args).unwrap();
}

fn enter_sub(_menu: &Menu<Output>, context: &mut Output) {
    writeln!(context, "In enter_sub").unwrap();
}

fn exit_sub(_menu: &Menu<Output>, context: &mut Output) {
    writeln!(context, "In exit_sub").unwrap();
}

fn select_baz<'a>(_menu: &Menu<Output>, _item: &Item<Output>, args: &[&str], context: &mut Output) {
    writeln!(context, "In select_baz: Args = {:?}", args).unwrap();
}

fn select_quux<'a>(
    _menu: &Menu<Output>,
    _item: &Item<Output>,
    args: &[&str],
    context: &mut Output,
) {
    writeln!(context, "In select_quux: Args = {:?}", args).unwrap();
}
