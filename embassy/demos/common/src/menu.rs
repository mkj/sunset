// This file was originally copied from "menu" crate by Jonathan Pallant
// licensed under MIT or Apache-2.0
// 5c0c0fd37608b8ae9e55b156c40bc740066b4d03

//! # Menu
//!
//! A basic command-line interface for `#![no_std]` Rust programs. Peforms
//! zero heap allocation.
#![no_std]
#![deny(missing_docs)]

/// The type of function we call when we enter/exit a menu.
pub type MenuCallbackFn<T> = fn(context: &mut T);

/// The type of function we call when we a valid command has been entered.
pub type ItemCallbackFn<T> = fn(item: &Item<T>, args: &[&str], context: &mut T);

#[derive(Debug)]
/// Describes a parameter to the command
pub enum Parameter<'a> {
    /// A mandatory positional parameter
    Mandatory {
        /// A name for this mandatory positional parameter
        parameter_name: &'a str,
        /// Help text
        help: Option<&'a str>,
    },
    /// An optional positional parameter. Must come after the mandatory positional arguments.
    Optional {
        /// A name for this optional positional parameter
        parameter_name: &'a str,
        /// Help text
        help: Option<&'a str>,
    },
    /// An optional named parameter with no argument (e.g. `--verbose` or `--dry-run`)
    Named {
        /// The bit that comes after the `--`
        parameter_name: &'a str,
        /// Help text
        help: Option<&'a str>,
    },
    /// A optional named parameter with argument (e.g. `--mode=foo` or `--level=3`)
    NamedValue {
        /// The bit that comes after the `--`
        parameter_name: &'a str,
        /// The bit that comes after the `--name=`, e.g. `INT` or `FILE`. It's mostly for help text.
        argument_name: &'a str,
        /// Help text
        help: Option<&'a str>,
    },
}

/// Do we enter a sub-menu when this command is entered, or call a specific
/// function?
pub enum ItemType<'a, T>
where
    T: 'a,
{
    /// Call a function when this command is entered
    Callback {
        /// The function to call
        function: ItemCallbackFn<T>,
        /// The list of parameters for this function. Pass an empty list if there aren't any.
        parameters: &'a [Parameter<'a>],
    },
    /// This item is a sub-menu you can enter
    Menu(&'a Menu<'a, T>),
    /// Internal use only - do not use
    _Dummy,
}

/// An `Item` is a what our menus are made from. Each item has a `name` which
/// you have to enter to select this item. Each item can also have zero or
/// more parameters, and some optional help text.
pub struct Item<'a, T>
where
    T: 'a,
{
    /// The word you need to enter to activate this item. It is recommended
    /// that you avoid whitespace in this string.
    pub command: &'a str,
    /// Optional help text. Printed if you enter `help`.
    pub help: Option<&'a str>,
    /// The type of this item - menu, callback, etc.
    pub item_type: ItemType<'a, T>,
}

/// A `Menu` is made of one or more `Item`s.
pub struct Menu<'a, T>
where
    T: 'a,
{
    /// Each menu has a label which is visible in the prompt, unless you are
    /// the root menu.
    pub label: &'a str,
    /// A slice of menu items in this menu.
    pub items: &'a [&'a Item<'a, T>],
    /// A function to call when this menu is entered. If this is the root menu, this is called when the runner is created.
    pub entry: Option<MenuCallbackFn<T>>,
    /// A function to call when this menu is exited. Never called for the root menu.
    pub exit: Option<MenuCallbackFn<T>>,
}

/// This structure handles the menu. You feed it bytes as they are read from
/// the console and it executes menu actions when commands are typed in
/// (followed by Enter).
pub struct Runner<'a, T>
where
    T: core::fmt::Write,
    T: 'a,
{
    buffer: &'a mut [u8],
    used: usize,
    /// Maximum four levels deep
    menus: [Option<&'a Menu<'a, T>>; 4],
    depth: usize,
    /// The context object the `Runner` carries around.
    pub context: T,
}

/// Looks for the named parameter in the parameter list of the item, then
/// finds the correct argument.
///
/// * Returns `Ok(None)` if `parameter_name` gives an optional or named
///   parameter and that argument was not given.
/// * Returns `Ok(arg)` if the argument corresponding to `parameter_name` was
///   found. `arg` is the empty string if the parameter was `Parameter::Named`
///   (and hence doesn't take a value).
/// * Returns `Err(())` if `parameter_name` was not in `item.parameter_list`
///   or `item` wasn't an Item::Callback
pub fn argument_finder<'a, T>(
    item: &'a Item<'a, T>,
    argument_list: &'a [&'a str],
    name_to_find: &'a str,
) -> Result<Option<&'a str>, ()> {
    if let ItemType::Callback { parameters, .. } = item.item_type {
        // Step 1 - Find `name_to_find` in the parameter list.
        let mut found_param = None;
        let mut mandatory_count = 0;
        let mut optional_count = 0;
        for param in parameters.iter() {
            match param {
                Parameter::Mandatory { parameter_name, .. } => {
                    mandatory_count += 1;
                    if *parameter_name == name_to_find {
                        found_param = Some((param, mandatory_count));
                    }
                }
                Parameter::Optional { parameter_name, .. } => {
                    optional_count += 1;
                    if *parameter_name == name_to_find {
                        found_param = Some((param, optional_count));
                    }
                }
                Parameter::Named { parameter_name, .. } => {
                    if *parameter_name == name_to_find {
                        found_param = Some((param, 0));
                    }
                }
                Parameter::NamedValue { parameter_name, .. } => {
                    if *parameter_name == name_to_find {
                        found_param = Some((param, 0));
                    }
                }
            }
        }
        // Step 2 - What sort of parameter is it?
        match found_param {
            // Step 2a - Mandatory Positional
            Some((Parameter::Mandatory { .. }, mandatory_idx)) => {
                // We want positional parameter number `mandatory_idx`.
                let mut positional_args_seen = 0;
                for arg in argument_list.iter().filter(|x| !x.starts_with("--")) {
                    // Positional
                    positional_args_seen += 1;
                    if positional_args_seen == mandatory_idx {
                        return Ok(Some(arg));
                    }
                }
                // Valid thing to ask for but we don't have it
                Ok(None)
            }
            // Step 2b - Optional Positional
            Some((Parameter::Optional { .. }, optional_idx)) => {
                // We want positional parameter number `mandatory_count + optional_idx`.
                let mut positional_args_seen = 0;
                for arg in argument_list.iter().filter(|x| !x.starts_with("--")) {
                    // Positional
                    positional_args_seen += 1;
                    if positional_args_seen == (mandatory_count + optional_idx) {
                        return Ok(Some(arg));
                    }
                }
                // Valid thing to ask for but we don't have it
                Ok(None)
            }
            // Step 2c - Named (e.g. `--verbose`)
            Some((Parameter::Named { parameter_name, .. }, _)) => {
                for arg in argument_list {
                    if arg.starts_with("--") && (&arg[2..] == *parameter_name) {
                        return Ok(Some(""));
                    }
                }
                // Valid thing to ask for but we don't have it
                Ok(None)
            }
            // Step 2d - NamedValue (e.g. `--level=123`)
            Some((Parameter::NamedValue { parameter_name, .. }, _)) => {
                let name_start = 2;
                let equals_start = name_start + parameter_name.len();
                let value_start = equals_start + 1;
                for arg in argument_list {
                    if arg.starts_with("--")
                        && (arg.len() >= value_start)
                        && (arg.get(equals_start..=equals_start) == Some("="))
                        && (arg.get(name_start..equals_start) == Some(*parameter_name))
                    {
                        return Ok(Some(&arg[value_start..]));
                    }
                }
                // Valid thing to ask for but we don't have it
                Ok(None)
            }
            // Step 2e - not found
            _ => Err(()),
        }
    } else {
        // Not an item with arguments
        Err(())
    }
}

enum Outcome {
    CommandProcessed,
    NeedMore,
}

impl<'a, T> Runner<'a, T>
where
    T: core::fmt::Write,
{
    /// Create a new `Runner`. You need to supply a top-level menu, and a
    /// buffer that the `Runner` can use. Feel free to pass anything as the
    /// `context` type - the only requirement is that the `Runner` can
    /// `write!` to the context, which it will do for all text output.
    pub fn new(menu: &'a Menu<'a, T>, buffer: &'a mut [u8], mut context: T) -> Runner<'a, T> {
        if let Some(cb_fn) = menu.entry {
            cb_fn(&mut context);
        }
        let mut r = Runner {
            menus: [Some(menu), None, None, None],
            depth: 0,
            buffer,
            used: 0,
            context,
        };
        r.prompt(true);
        r
    }

    /// Print out a new command prompt, including sub-menu names if
    /// applicable.
    pub fn prompt(&mut self, newline: bool) {
        if newline {
            writeln!(self.context).unwrap();
        }
        if self.depth != 0 {
            let mut depth = 1;
            while depth <= self.depth {
                if depth > 1 {
                    write!(self.context, "/").unwrap();
                }
                write!(self.context, "/{}", self.menus[depth].unwrap().label).unwrap();
                depth += 1;
            }
        }
        write!(self.context, "> ").unwrap();
    }

    fn backspace(&mut self) {
        if self.used > 0 {
            let _ = write!(self.context, "\u{0008} \u{0008}");
            self.used -= 1;
        }
    }

    fn previous(&mut self) -> Option<u8> {
        if self.used == 0 {
            None
        } else {
            Some(self.buffer[self.used-1])
        }
    }


    /// Add a byte to the menu runner's buffer. If this byte is a
    /// carriage-return, the buffer is scanned and the appropriate action
    /// performed.
    /// By default, an echo feature is enabled to display commands on the terminal.
    pub fn input_byte(&mut self, input: u8) {

        // Strip carriage returns
        if input == 0x0A {
            return;
        }
        let outcome = if input == 0x0D {
            // Handle the command
            self.process_command();
            Outcome::CommandProcessed
        } else if input == 0x03 {
            // Handling ctrl-c, clear current command
            Outcome::CommandProcessed
        } else if (input == 0x08) || (input == 0x7F) {
            // Handling backspace or delete
            self.backspace();
            Outcome::NeedMore
        } else if input == 0x15 {
            // Handling ctrl-u, delete to start of line
            while self.used > 0 {
                self.backspace();
            }
            Outcome::NeedMore
        } else if input == 0x17 {
            // Handling ctrl-w, delete previous word
            while self.previous() == Some(b' ') {
                self.backspace();
            }
            while self.used > 0 && self.buffer[self.used-1] != b' ' {
                self.backspace();
            }
            Outcome::NeedMore
        } else if self.used < self.buffer.len() {
            self.buffer[self.used] = input;
            self.used += 1;

            // #[cfg(feature = "echo")]
            {
                // We have to do this song and dance because `self.prompt()` needs
                // a mutable reference to self, and we can't have that while
                // holding a reference to the buffer at the same time.
                // This line grabs the buffer, checks it's OK, then releases it again
                let valid = core::str::from_utf8(&self.buffer[0..self.used]).is_ok();
                // Now we've released the buffer, we can draw the prompt
                if valid {
                    write!(self.context, "\r").unwrap();
                    self.prompt(false);
                }
                // Grab the buffer again to render it to the screen
                if let Ok(s) = core::str::from_utf8(&self.buffer[0..self.used]) {
                    write!(self.context, "{}", s).unwrap();
                }
            }
            Outcome::NeedMore
        } else {
            writeln!(self.context, "Buffer overflow!").unwrap();
            Outcome::NeedMore
        };
        match outcome {
            Outcome::CommandProcessed => {
                self.used = 0;
                self.prompt(true);
            }
            Outcome::NeedMore => {}
        }
    }

    /// Scan the buffer and do the right thing based on its contents.
    fn process_command(&mut self) {
        // Go to the next line, below the prompt
        writeln!(self.context).unwrap();
        if let Ok(command_line) = core::str::from_utf8(&self.buffer[0..self.used]) {
            // We have a valid string
            let mut parts = command_line.split_whitespace();
            if let Some(cmd) = parts.next() {
                let menu = self.menus[self.depth].unwrap();
                if cmd == "help" {
                    match parts.next() {
                        Some(arg) => match menu.items.iter().find(|i| i.command == arg) {
                            Some(item) => {
                                self.print_long_help(&item);
                            }
                            None => {
                                writeln!(self.context, "I can't help with {:?}", arg).unwrap();
                            }
                        },
                        _ => {
                            writeln!(self.context, "AVAILABLE ITEMS:").unwrap();
                            for item in menu.items {
                                self.print_short_help(&item);
                            }
                            if self.depth != 0 {
                                self.print_short_help(&Item {
                                    command: "exit",
                                    help: Some("Leave this menu."),
                                    item_type: ItemType::_Dummy,
                                });
                            }
                            self.print_short_help(&Item {
                                command: "help [ <command> ]",
                                help: Some("Show this help, or get help on a specific command."),
                                item_type: ItemType::_Dummy,
                            });
                        }
                    }
                } else if cmd == "exit" && self.depth != 0 {
                    self.menus[self.depth] = None;
                    self.depth -= 1;
                } else {
                    let mut found = false;
                    for item in menu.items {
                        if cmd == item.command {
                            match item.item_type {
                                ItemType::Callback {
                                    function,
                                    parameters,
                                } => Self::call_function(
                                    &mut self.context,
                                    function,
                                    parameters,
                                    item,
                                    command_line,
                                ),
                                ItemType::Menu(m) => {
                                    self.depth += 1;
                                    self.menus[self.depth] = Some(m);
                                }
                                ItemType::_Dummy => {
                                    unreachable!();
                                }
                            }
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        writeln!(self.context, "Command {:?} not found. Try 'help'.", cmd).unwrap();
                    }
                }
            } else {
                writeln!(self.context, "Input was empty?").unwrap();
            }
        } else {
            // Hmm ..  we did not have a valid string
            writeln!(self.context, "Input was not valid UTF-8").unwrap();
        }
    }

    fn print_short_help(&mut self, item: &Item<T>) {
        let mut has_options = false;
        match item.item_type {
            ItemType::Callback { parameters, .. } => {
                write!(self.context, "  {}", item.command).unwrap();
                if !parameters.is_empty() {
                    for param in parameters.iter() {
                        match param {
                            Parameter::Mandatory { parameter_name, .. } => {
                                write!(self.context, " <{}>", parameter_name).unwrap();
                            }
                            Parameter::Optional { parameter_name, .. } => {
                                write!(self.context, " [ <{}> ]", parameter_name).unwrap();
                            }
                            Parameter::Named { .. } => {
                                has_options = true;
                            }
                            Parameter::NamedValue { .. } => {
                                has_options = true;
                            }
                        }
                    }
                }
            }
            ItemType::Menu(_menu) => {
                write!(self.context, "  {}", item.command).unwrap();
            }
            ItemType::_Dummy => {
                write!(self.context, "  {}", item.command).unwrap();
            }
        }
        if has_options {
            write!(self.context, " [OPTIONS...]").unwrap();
        }
        writeln!(self.context).unwrap();
    }

    fn print_long_help(&mut self, item: &Item<T>) {
        writeln!(self.context, "SUMMARY:").unwrap();
        match item.item_type {
            ItemType::Callback { parameters, .. } => {
                write!(self.context, "  {}", item.command).unwrap();
                if !parameters.is_empty() {
                    for param in parameters.iter() {
                        match param {
                            Parameter::Mandatory { parameter_name, .. } => {
                                write!(self.context, " <{}>", parameter_name).unwrap();
                            }
                            Parameter::Optional { parameter_name, .. } => {
                                write!(self.context, " [ <{}> ]", parameter_name).unwrap();
                            }
                            Parameter::Named { parameter_name, .. } => {
                                write!(self.context, " [ --{} ]", parameter_name).unwrap();
                            }
                            Parameter::NamedValue {
                                parameter_name,
                                argument_name,
                                ..
                            } => {
                                write!(self.context, " [ --{}={} ]", parameter_name, argument_name)
                                    .unwrap();
                            }
                        }
                    }
                    writeln!(self.context, "\n\nPARAMETERS:").unwrap();
                    let default_help = "Undocumented option";
                    for param in parameters.iter() {
                        match param {
                            Parameter::Mandatory {
                                parameter_name,
                                help,
                            } => {
                                writeln!(
                                    self.context,
                                    "  <{0}>\n    {1}\n",
                                    parameter_name,
                                    help.unwrap_or(default_help),
                                )
                                .unwrap();
                            }
                            Parameter::Optional {
                                parameter_name,
                                help,
                            } => {
                                writeln!(
                                    self.context,
                                    "  <{0}>\n    {1}\n",
                                    parameter_name,
                                    help.unwrap_or(default_help),
                                )
                                .unwrap();
                            }
                            Parameter::Named {
                                parameter_name,
                                help,
                            } => {
                                writeln!(
                                    self.context,
                                    "  --{0}\n    {1}\n",
                                    parameter_name,
                                    help.unwrap_or(default_help),
                                )
                                .unwrap();
                            }
                            Parameter::NamedValue {
                                parameter_name,
                                argument_name,
                                help,
                            } => {
                                writeln!(
                                    self.context,
                                    "  --{0}={1}\n    {2}\n",
                                    parameter_name,
                                    argument_name,
                                    help.unwrap_or(default_help),
                                )
                                .unwrap();
                            }
                        }
                    }
                }
            }
            ItemType::Menu(_menu) => {
                write!(self.context, "  {}", item.command).unwrap();
            }
            ItemType::_Dummy => {
                write!(self.context, "  {}", item.command).unwrap();
            }
        }
        if let Some(help) = item.help {
            writeln!(self.context, "\n\nDESCRIPTION:\n{}", help).unwrap();
        }
    }

    fn call_function(
        context: &mut T,
        callback_function: ItemCallbackFn<T>,
        parameters: &[Parameter],
        item: &Item<T>,
        command: &str,
    ) {
        let mandatory_parameter_count = parameters
            .iter()
            .filter(|p| match p {
                Parameter::Mandatory { .. } => true,
                _ => false,
            })
            .count();
        let positional_parameter_count = parameters
            .iter()
            .filter(|p| match p {
                Parameter::Mandatory { .. } => true,
                Parameter::Optional { .. } => true,
                _ => false,
            })
            .count();
        if command.len() >= item.command.len() {
            // Maybe arguments
            let mut argument_buffer: [&str; 16] = [""; 16];
            let mut argument_count = 0;
            let mut positional_arguments = 0;
            for (slot, arg) in argument_buffer
                .iter_mut()
                .zip(command[item.command.len()..].split_whitespace())
            {
                *slot = arg;
                argument_count += 1;
                if arg.starts_with("--") {
                    // Validate named argument
                    let mut found = false;
                    for param in parameters.iter() {
                        match param {
                            Parameter::Named { parameter_name, .. } => {
                                if &arg[2..] == *parameter_name {
                                    found = true;
                                    break;
                                }
                            }
                            Parameter::NamedValue { parameter_name, .. } => {
                                if arg.contains('=') {
                                    if let Some(given_name) = arg[2..].split('=').next() {
                                        if given_name == *parameter_name {
                                            found = true;
                                            break;
                                        }
                                    }
                                }
                            }
                            _ => {
                                // Ignore
                            }
                        }
                    }
                    if !found {
                        writeln!(context, "Error: Did not understand {:?}", arg).unwrap();
                        return;
                    }
                } else {
                    positional_arguments += 1;
                }
            }
            if positional_arguments < mandatory_parameter_count {
                writeln!(context, "Error: Insufficient arguments given").unwrap();
            } else if positional_arguments > positional_parameter_count {
                writeln!(context, "Error: Too many arguments given").unwrap();
            } else {
                callback_function(
                    item,
                    &argument_buffer[0..argument_count],
                    context,
                );
            }
        } else {
            // Definitely no arguments
            if mandatory_parameter_count == 0 {
                callback_function(item, &[], context);
            } else {
                writeln!(context, "Error: Insufficient arguments given").unwrap();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy(_item: &Item<u32>, _args: &[&str], _context: &mut u32) {}

    #[test]
    fn find_arg_mandatory() {
        let item = Item {
            command: "dummy",
            help: None,
            item_type: ItemType::Callback {
                function: dummy,
                parameters: &[
                    Parameter::Mandatory {
                        parameter_name: "foo",
                        help: Some("Some help for foo"),
                    },
                    Parameter::Mandatory {
                        parameter_name: "bar",
                        help: Some("Some help for bar"),
                    },
                    Parameter::Mandatory {
                        parameter_name: "baz",
                        help: Some("Some help for baz"),
                    },
                ],
            },
        };
        assert_eq!(
            argument_finder(&item, &["a", "b", "c"], "foo"),
            Ok(Some("a"))
        );
        assert_eq!(
            argument_finder(&item, &["a", "b", "c"], "bar"),
            Ok(Some("b"))
        );
        assert_eq!(
            argument_finder(&item, &["a", "b", "c"], "baz"),
            Ok(Some("c"))
        );
        // Not an argument
        assert_eq!(argument_finder(&item, &["a", "b", "c"], "quux"), Err(()));
    }

    #[test]
    fn find_arg_optional() {
        let item = Item {
            command: "dummy",
            help: None,
            item_type: ItemType::Callback {
                function: dummy,
                parameters: &[
                    Parameter::Mandatory {
                        parameter_name: "foo",
                        help: Some("Some help for foo"),
                    },
                    Parameter::Mandatory {
                        parameter_name: "bar",
                        help: Some("Some help for bar"),
                    },
                    Parameter::Optional {
                        parameter_name: "baz",
                        help: Some("Some help for baz"),
                    },
                ],
            },
        };
        assert_eq!(
            argument_finder(&item, &["a", "b", "c"], "foo"),
            Ok(Some("a"))
        );
        assert_eq!(
            argument_finder(&item, &["a", "b", "c"], "bar"),
            Ok(Some("b"))
        );
        assert_eq!(
            argument_finder(&item, &["a", "b", "c"], "baz"),
            Ok(Some("c"))
        );
        // Not an argument
        assert_eq!(argument_finder(&item, &["a", "b", "c"], "quux"), Err(()));
        // Missing optional
        assert_eq!(argument_finder(&item, &["a", "b"], "baz"), Ok(None));
    }

    #[test]
    fn find_arg_named() {
        let item = Item {
            command: "dummy",
            help: None,
            item_type: ItemType::Callback {
                function: dummy,
                parameters: &[
                    Parameter::Mandatory {
                        parameter_name: "foo",
                        help: Some("Some help for foo"),
                    },
                    Parameter::Named {
                        parameter_name: "bar",
                        help: Some("Some help for bar"),
                    },
                    Parameter::Named {
                        parameter_name: "baz",
                        help: Some("Some help for baz"),
                    },
                ],
            },
        };
        assert_eq!(
            argument_finder(&item, &["a", "--bar", "--baz"], "foo"),
            Ok(Some("a"))
        );
        assert_eq!(
            argument_finder(&item, &["a", "--bar", "--baz"], "bar"),
            Ok(Some(""))
        );
        assert_eq!(
            argument_finder(&item, &["a", "--bar", "--baz"], "baz"),
            Ok(Some(""))
        );
        // Not an argument
        assert_eq!(
            argument_finder(&item, &["a", "--bar", "--baz"], "quux"),
            Err(())
        );
        // Missing named
        assert_eq!(argument_finder(&item, &["a"], "baz"), Ok(None));
    }

    #[test]
    fn find_arg_namedvalue() {
        let item = Item {
            command: "dummy",
            help: None,
            item_type: ItemType::Callback {
                function: dummy,
                parameters: &[
                    Parameter::Mandatory {
                        parameter_name: "foo",
                        help: Some("Some help for foo"),
                    },
                    Parameter::Named {
                        parameter_name: "bar",
                        help: Some("Some help for bar"),
                    },
                    Parameter::NamedValue {
                        parameter_name: "baz",
                        argument_name: "TEST",
                        help: Some("Some help for baz"),
                    },
                ],
            },
        };
        assert_eq!(
            argument_finder(&item, &["a", "--bar", "--baz"], "foo"),
            Ok(Some("a"))
        );
        assert_eq!(
            argument_finder(&item, &["a", "--bar", "--baz"], "bar"),
            Ok(Some(""))
        );
        // No argument so mark as not found
        assert_eq!(
            argument_finder(&item, &["a", "--bar", "--baz"], "baz"),
            Ok(None)
        );
        // Empty argument
        assert_eq!(
            argument_finder(&item, &["a", "--bar", "--baz="], "baz"),
            Ok(Some(""))
        );
        // Short argument
        assert_eq!(
            argument_finder(&item, &["a", "--bar", "--baz=1"], "baz"),
            Ok(Some("1"))
        );
        // Long argument
        assert_eq!(
            argument_finder(
                &item,
                &["a", "--bar", "--baz=abcdefghijklmnopqrstuvwxyz"],
                "baz"
            ),
            Ok(Some("abcdefghijklmnopqrstuvwxyz"))
        );
        // Not an argument
        assert_eq!(
            argument_finder(&item, &["a", "--bar", "--baz"], "quux"),
            Err(())
        );
        // Missing named
        assert_eq!(argument_finder(&item, &["a"], "baz"), Ok(None));
    }
}
