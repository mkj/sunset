use menu::*;
pub use crate::server::BufOutput;
use core::fmt::Write;

// from menu crate examples/simple.rs

pub const ROOT_MENU: Menu<BufOutput> = Menu {
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

fn enter_root(_menu: &Menu<BufOutput>, context: &mut BufOutput) {
    writeln!(context, "In enter_root").unwrap();
}

fn exit_root(_menu: &Menu<BufOutput>, context: &mut BufOutput) {
    writeln!(context, "In exit_root").unwrap();
}

fn select_foo<'a>(_menu: &Menu<BufOutput>, item: &Item<BufOutput>, args: &[&str], context: &mut BufOutput) {
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

fn select_bar<'a>(_menu: &Menu<BufOutput>, _item: &Item<BufOutput>, args: &[&str], context: &mut BufOutput) {
    writeln!(context, "In select_bar. Args = {:?}", args).unwrap();
}

fn enter_sub(_menu: &Menu<BufOutput>, context: &mut BufOutput) {
    writeln!(context, "In enter_sub").unwrap();
}

fn exit_sub(_menu: &Menu<BufOutput>, context: &mut BufOutput) {
    writeln!(context, "In exit_sub").unwrap();
}

fn select_baz<'a>(_menu: &Menu<BufOutput>, _item: &Item<BufOutput>, args: &[&str], context: &mut BufOutput) {
    writeln!(context, "In select_baz: Args = {:?}", args).unwrap();
}

fn select_quux<'a>(
    _menu: &Menu<BufOutput>,
    _item: &Item<BufOutput>,
    args: &[&str],
    context: &mut BufOutput,
) {
    writeln!(context, "In select_quux: Args = {:?}", args).unwrap();
}
