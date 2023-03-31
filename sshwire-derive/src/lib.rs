//! Used in conjunction with `sshwire.rs` and `packets.rs`
//!
//! `SSHWIRE_DEBUG` environment variable can be set at build time
//! to write generated files to the `target/` directory.

use std::collections::HashSet;
use std::env;

use proc_macro::Delimiter;
use virtue::generate::FnSelfArg;
use virtue::parse::{Attribute, AttributeLocation, EnumBody, StructBody};
use virtue::utils::{parse_tagged_attribute, ParsedAttribute};
use virtue::prelude::*;

const ENV_SSHWIRE_DEBUG: &'static str = &"SSHWIRE_DEBUG";

#[proc_macro_derive(SSHEncode, attributes(sshwire))]
pub fn derive_encode(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let r = encode_inner(input).unwrap_or_else(|e| e.into_token_stream());
    r
}

#[proc_macro_derive(SSHDecode, attributes(sshwire))]
pub fn derive_decode(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    decode_inner(input).unwrap_or_else(|e| e.into_token_stream())
}

fn encode_inner(input: TokenStream) -> Result<TokenStream> {
    let parse = Parse::new(input)?;
    let (mut gen, att, body) = parse.into_generator();
    // println!("att {att:#?}");
    match body {
        Body::Struct(body) => {
            encode_struct(&mut gen, body)?;
        }
        Body::Enum(body) => {
            encode_enum(&mut gen, &att, body)?;
        }
    }
    if env::var(ENV_SSHWIRE_DEBUG).is_ok() {
        gen.export_to_file("sshwire", "SSHEncode");
    }
    gen.finish()
}

fn decode_inner(input: TokenStream) -> Result<TokenStream> {
    let parse = Parse::new(input)?;
    let (mut gen, att, body) = parse.into_generator();
    // println!("att {att:#?}");
    match body {
        Body::Struct(body) => {
            decode_struct(&mut gen, body)?;
        }
        Body::Enum(body) => {
            decode_enum(&mut gen, &att, body)?;
        }
    }
    if env::var(ENV_SSHWIRE_DEBUG).is_ok() {
        gen.export_to_file("sshwire", "SSHDecode");
    }
    gen.finish()
}

#[derive(Debug)]
enum ContainerAtt {
    /// The string of the method is prefixed to this enum.
    /// `#[sshwire(variant_prefix)]`
    VariantPrefix,

    /// Don't generate SSHEncodeEnum. Can't be used with SSHDecode derive.
    /// `#[sshwire(no_variant_names)]`
    NoNames,
}

#[derive(Debug)]
enum FieldAtt {
    /// A variant method name will be encoded/decoded before the next field.
    /// eg `#[sshwire(variant_name = ch)]` for `ChannelRequest`
    VariantName(Ident),
    /// Any unknown variant name should be recorded here.
    /// This variant can't be written out.
    /// `#[sshwire(unknown))]`
    CaptureUnknown,
    /// The name of a variant, used by the parent struct
    /// `#[sshwire(variant = "exit-signal"))]`
    /// or
    /// `#[sshwire(variant = SSH_NAME_IDENT))]`
    Variant(TokenTree),
}

fn take_cont_atts(atts: &[Attribute]) -> Result<Vec<ContainerAtt>> {
    let x = atts.iter()
        .filter_map(|a| {
            parse_tagged_attribute(&a.tokens, "sshwire")
            .transpose()
        });

    let mut ret = vec![];
    // flatten the lists
    for a in x {
        for a in a? {
            let l = match a {
                ParsedAttribute::Tag(l) if l.to_string() == "no_variant_names" => Ok(ContainerAtt::NoNames),
                ParsedAttribute::Tag(l) if l.to_string() == "variant_prefix" => Ok(ContainerAtt::VariantPrefix),
                _ => Err(Error::Custom {
                    error: "Unknown sshwire atttribute".into(),
                    span: None,
                }),
            }?;
            ret.push(l);
        }
    }
    Ok(ret)
}

// TODO: we could use virtue parse_tagged_attribute() though it doesn't support Literals
fn take_field_atts(atts: &[Attribute]) -> Result<Vec<FieldAtt>> {
    atts.iter()
        .filter_map(|a| {
            match a.location {
                AttributeLocation::Field | AttributeLocation::Variant => {
                    let mut s = a.tokens.stream().into_iter();
                    if &s.next().expect("missing attribute name").to_string()
                        != "sshwire"
                    {
                        // skip attributes other than "sshwire"
                        return None;
                    }
                    Some(if let Some(TokenTree::Group(g)) = s.next() {
                        let mut g = g.stream().into_iter();
                        let f = match g.next() {
                            Some(TokenTree::Ident(l))
                                if l.to_string() == "variant_name" =>
                            {
                                // check for '='
                                match g.next() {
                                    Some(TokenTree::Punct(p)) if p == '=' => (),
                                    _ => {
                                        return Some(Err(Error::Custom {
                                            error: "Missing '='".into(),
                                            span: Some(a.tokens.span()),
                                        }))
                                    }
                                }
                                match g.next() {
                                    Some(TokenTree::Ident(i)) => {
                                        Ok(FieldAtt::VariantName(i))
                                    }
                                    _ => Err(Error::ExpectedIdent(a.tokens.span())),
                                }
                            }

                            Some(TokenTree::Ident(l))
                                if l.to_string() == "unknown" =>
                            {
                                Ok(FieldAtt::CaptureUnknown)
                            }

                            Some(TokenTree::Ident(l))
                                if l.to_string() == "variant" =>
                            {
                                // check for '='
                                match g.next() {
                                    Some(TokenTree::Punct(p)) if p == '=' => (),
                                    _ => {
                                        return Some(Err(Error::Custom {
                                            error: "Missing '='".into(),
                                            span: Some(a.tokens.span()),
                                        }))
                                    }
                                }
                                if let Some(t) = g.next() {
                                    Ok(FieldAtt::Variant(t))
                                } else {
                                    Err(Error::Custom {
                                        error: "Missing expression".into(),
                                        span: Some(a.tokens.span()),
                                    })
                                }
                            }

                            _ => Err(Error::Custom {
                                error: "Unknown sshwire atttribute".into(),
                                span: Some(a.tokens.span()),
                            }),
                        };

                        if let Some(_) = g.next() {
                            Err(Error::Custom {
                                error: "Extra unhandled parts".into(),
                                span: Some(a.tokens.span()),
                            })
                        } else {
                            f
                        }
                    } else {
                        Err(Error::Custom {
                            error: "#[sshwire(...)] attribute is missing (...) part"
                                .into(),
                            span: Some(a.tokens.span()),
                        })
                    })
                }
                _ => panic!("Non-field attribute for field: {a:#?}"),
            }
        })
        .collect()
}

fn encode_struct(gen: &mut Generator, body: StructBody) -> Result<()> {
    gen.impl_for("crate::sshwire::SSHEncode")
        .generate_fn("enc")
        .with_generic_deps("E", ["crate::sshwire::SSHSink"])
        .with_self_arg(FnSelfArg::RefSelf)
        .with_arg("s", "&mut E")
        .with_return_type("crate::sshwire::WireResult<()>")
        .body(|fn_body| {
            match &body.fields {
                Some(Fields::Tuple(v)) => {
                    for (fname, f) in v.iter().enumerate() {
                        // we're only using single elements for newtype, don't bother with atts for now
                        if !f.attributes.is_empty() {
                            return Err(Error::Custom { error: "Attributes aren't allowed for tuple structs".into(), span: Some(f.span()) })
                        }
                        fn_body.push_parsed(format!("crate::sshwire::SSHEncode::enc(&self.{fname}, s)?;"))?;
                    }
                }
                Some(Fields::Struct(v)) => {
                    for f in v {
                        let fname = &f.0;
                        let atts = take_field_atts(&f.1.attributes)?;
                        for a in atts {
                            if let FieldAtt::VariantName(enum_field) = a {
                                // encode an enum field's variant name before this field
                                fn_body.push_parsed(format!("crate::sshwire::SSHEncode::enc(&self.{enum_field}.variant_name()?, s)?;"))?;
                            }
                        }
                        fn_body.push_parsed(format!("crate::sshwire::SSHEncode::enc(&self.{fname}, s)?;"))?;
                    }

                }
                None => {
                    // nothing to do.
                    // either an empty braced struct or a unit struct.
                }

            }
            fn_body.push_parsed("Ok(())")?;
            Ok(())
        })?;
    Ok(())
}

fn encode_enum(
    gen: &mut Generator,
    atts: &[Attribute],
    body: EnumBody,
) -> Result<()> {

    let cont_atts = take_cont_atts(atts)?;

    gen.impl_for("crate::sshwire::SSHEncode")
        .generate_fn("enc")
        .with_generic_deps("S", ["crate::sshwire::SSHSink"])
        .with_self_arg(FnSelfArg::RefSelf)
        .with_arg("s", "&mut S")
        .with_return_type("crate::sshwire::WireResult<()>")
        .body(|fn_body| {
            if cont_atts.iter().any(|c| matches!(c, ContainerAtt::VariantPrefix)) {
                fn_body.push_parsed("crate::sshwire::SSHEncode::enc(&self.variant_name()?, s)?;")?;
            }

            fn_body.ident_str("match");
            fn_body.puncts("*");
            fn_body.ident_str("self");
            fn_body.group(Delimiter::Brace, |match_arm| {
                for var in &body.variants {
                    match_arm.ident_str("Self");
                    match_arm.puncts("::");
                    match_arm.ident(var.name.clone());

                    let atts = take_field_atts(&var.attributes)?;

                    let mut rhs = StreamBuilder::new();
                    match var.fields {
                        None => {
                            // Unit enum
                        }
                        Some(Fields::Tuple(ref f)) if f.len() == 1 => {
                            match_arm.group(Delimiter::Parenthesis, |item| {
                                item.ident_str("ref");
                                item.ident_str("i");
                                Ok(())
                            })?;
                            if atts.iter().any(|a| matches!(a, FieldAtt::CaptureUnknown)) {
                                rhs.push_parsed("return Err(crate::sshwire::WireError::UnknownVariant)")?;
                            } else {
                                rhs.push_parsed(format!("crate::sshwire::SSHEncode::enc(i, s)?;"))?;
                            }

                        }
                        _ => return Err(Error::Custom { error: "SSHEncode currently only implements Unit or single value enum variants.".into(), span: None})
                    }

                    match_arm.puncts("=>");
                    match_arm.group(Delimiter::Brace, |var_body| {
                        var_body.append(rhs);
                        Ok(())
                    })?;
                }
                Ok(())
            })?;
            fn_body.push_parsed("Ok(())")?;
            Ok(())
        })?;

    if !cont_atts.iter().any(|c| matches!(c, ContainerAtt::NoNames)) {
        encode_enum_names(gen, atts, body)?;
    }
    Ok(())
}

fn field_att_var_names(name: &Ident, mut atts: Vec<FieldAtt>) -> Result<TokenTree> {
    let mut v = vec![];
    while let Some(p) = atts.pop() {
        if let FieldAtt::Variant(t) = p {
            v.push(t);
        }
    }
    if v.len() != 1 {
        return Err(Error::Custom { error: format!("One #[sshwire(variant = ...)] attribute is required for each enum field, missing for {:?}", name), span: None});
    }
    Ok(v.pop().unwrap())
}

fn encode_enum_names(
    gen: &mut Generator,
    _atts: &[Attribute],
    body: EnumBody,
) -> Result<()> {
    gen.impl_for("crate::sshwire::SSHEncodeEnum")
        .generate_fn("variant_name")
        .with_self_arg(FnSelfArg::RefSelf)
        .with_return_type("crate::sshwire::WireResult<&'static str>")
        .body(|fn_body| {
            fn_body.push_parsed("let r = match self")?;
            fn_body.group(Delimiter::Brace, |match_arm| {
                for var in &body.variants {
                    match_arm.ident_str("Self");
                    match_arm.puncts("::");
                    match_arm.ident(var.name.clone());

                    let mut rhs = StreamBuilder::new();
                    let atts = take_field_atts(&var.attributes)?;
                    if atts.iter().any(|a| matches!(a, FieldAtt::CaptureUnknown)) {
                        rhs.push_parsed("return Err(crate::sshwire::WireError::UnknownVariant)")?;
                    } else {
                        rhs.push(field_att_var_names(&var.name, atts)?);
                    }

                    match var.fields {
                        None => {
                            // nothing to do
                        }
                        Some(Fields::Tuple(ref f)) if f.len() == 1 => {
                            match_arm.group(Delimiter::Parenthesis, |item| {
                                item.ident_str("_");
                                Ok(())
                            })?;

                        }
                        _ => return Err(Error::Custom { error: "SSHEncode currently only implements Unit or single value enum variants.".into(), span: None})
                    }

                    match_arm.puncts("=>");
                    match_arm.group(Delimiter::Brace, |var_body| {
                        var_body.append(rhs);
                        Ok(())
                    })?;
                }
                Ok(())
            })?;
            fn_body.push_parsed("; Ok(r)")?;

            Ok(())
        })?;

    Ok(())
}

fn decode_struct(gen: &mut Generator, body: StructBody) -> Result<()> {
    gen.impl_for_with_lifetimes("crate::sshwire::SSHDecode", ["de"])
        .modify_generic_constraints(|generics, where_constraints| {
            for lt in generics.iter_lifetimes() {
                where_constraints.push_parsed_constraint(format!("'de: '{}", lt.ident))?;
            }
            Ok(())
        })?
        .generate_fn("dec")
        .with_generic_deps("S", ["crate::sshwire::SSHSource<'de>"])
        .with_arg("s", "&mut S")
        .with_return_type("crate::sshwire::WireResult<Self>")
        .body(|fn_body| {
            let mut named_enums = HashSet::new();
            if let Some(Fields::Struct(v)) = &body.fields {
                for f in v {
                    let atts = take_field_atts(&f.1.attributes)?;
                    for a in atts {
                        if let FieldAtt::VariantName(enum_field) = a {
                            // Read the extra field on the wire that isn't directly included in the struct
                            named_enums.insert(enum_field.to_string());
                            fn_body.push_parsed(format!("let enum_name_{enum_field}: BinString = crate::sshwire::SSHDecode::dec(s)?;"))?;
                        }
                    }
                    let fname = &f.0;
                    if named_enums.contains(&fname.to_string()) {
                        fn_body.push_parsed(format!("let field_{fname} =  crate::sshwire::SSHDecodeEnum::dec_enum(s, enum_name_{fname}.0)?;"))?;
                    } else {
                        fn_body.push_parsed(format!("let field_{fname} = crate::sshwire::SSHDecode::dec(s)?;"))?;
                    }
                }
            }
            fn_body.ident_str("Ok");
            fn_body.group(Delimiter::Parenthesis, |fn_body| {
                match &body.fields {
                    Some(Fields::Tuple(f)) => {
                        // we don't handle attributes for Tuple Structs - only use as newtype
                        fn_body.ident_str("Self");
                        fn_body.group(Delimiter::Parenthesis, |args| {
                            for _ in f.iter() {
                                args.push_parsed(format!("crate::sshwire::SSHDecode::dec(s)?,"))?;
                            }
                            Ok(())
                        })?;
                    }
                    Some(Fields::Struct(v)) => {
                        fn_body.ident_str("Self");
                        fn_body.group(Delimiter::Brace, |args| {
                            for f in v {
                                let fname = &f.0;
                                args.push_parsed(format!("{fname}: field_{fname},"))?;
                            }
                            Ok(())
                        })?;
                    }
                    None => {
                        // An empty struct (or unit or empty tuple-struct)
                        fn_body.ident_str("Self");
                        fn_body.group(Delimiter::Brace, |_| Ok(()))?;
                    }
                }
                Ok(())
            })?;
            Ok(())
        })?;
    Ok(())
}

fn decode_enum(
    gen: &mut Generator,
    atts: &[Attribute],
    body: EnumBody,
) -> Result<()> {
    let cont_atts = take_cont_atts(atts)?;

    if cont_atts.iter().any(|c| matches!(c, ContainerAtt::NoNames)) {
        return Err(Error::Custom {
            error:
                "SSHDecode derive can't be used with #[sshwire(no_variant_names)]"
                    .into(),
            span: None,
        });
    }

    // SSHDecode trait if it is self describing
    if cont_atts.iter().any(|c| matches!(c, ContainerAtt::VariantPrefix)) {
        decode_enum_variant_prefix(gen, atts, &body)?;
    }

    decode_enum_names(gen, atts, &body)?;
    Ok(())
}

fn decode_enum_variant_prefix(
    gen: &mut Generator,
    _atts: &[Attribute],
    _body: &EnumBody,
) -> Result<()> {
    gen.impl_for_with_lifetimes("crate::sshwire::SSHDecode", ["de"])
        .modify_generic_constraints(|generics, where_constraints| {
            for lt in generics.iter_lifetimes() {
                where_constraints.push_parsed_constraint(format!("'de: '{}", lt.ident))?;
            }
            Ok(())
        })?
        .generate_fn("dec")
        .with_generic_deps("S", ["crate::sshwire::SSHSource<'de>"])
        .with_arg("s", "&mut S")
        .with_return_type("crate::sshwire::WireResult<Self>")
        .body(|fn_body| {
            fn_body
                .push_parsed("let variant: crate::sshwire::BinString = crate::sshwire::SSHDecode::dec(s)?;")?;
            fn_body.push_parsed(
                "crate::sshwire::SSHDecodeEnum::dec_enum(s, variant.0)",
            )?;
            Ok(())
        })
}

fn decode_enum_names(
    gen: &mut Generator,
    _atts: &[Attribute],
    body: &EnumBody,
) -> Result<()> {
    gen.impl_for_with_lifetimes("crate::sshwire::SSHDecodeEnum", ["de"])
        .modify_generic_constraints(|generics, where_constraints| {
            for lt in generics.iter_lifetimes() {
                where_constraints.push_parsed_constraint(format!("'de: '{}", lt.ident))?;
            }
            Ok(())
        })?
        .generate_fn("dec_enum")
        .with_generic_deps("S", ["crate::sshwire::SSHSource<'de>"])
        .with_arg("s", "&mut S")
        .with_arg("variant", "&'de [u8]")
        .with_return_type("crate::sshwire::WireResult<Self>")
        .body(|fn_body| {
            // Some(ascii_string), or None
            fn_body.push_parsed("let var_str = crate::sshwire::try_as_ascii_str(variant).ok();")?;

            fn_body.push_parsed("let r = match var_str")?;
            fn_body.group(Delimiter::Brace, |match_arm| {
                let mut unknown_arm = None;
                for var in &body.variants {
                    let atts = take_field_atts(&var.attributes)?;
                    if atts.iter().any(|a| matches!(a, FieldAtt::CaptureUnknown)) {
                        // create the Unknown fallthrough but it will be at the end of the match list
                        let mut m = StreamBuilder::new();
                        m.push_parsed(format!("_ => {{ s.ctx().seen_unknown = true; Self::{}(Unknown(variant))}}", var.name))?;
                        if unknown_arm.replace(m).is_some() {
                            return Err(Error::Custom { error: "only one variant can have #[sshwire(unknown)]".into(), span: None})
                        }
                    } else {
                        let var_name = field_att_var_names(&var.name, atts)?;
                        match_arm.push_parsed(format!("Some({}) => ", var_name))?;
                        match_arm.group(Delimiter::Brace, |var_body| {
                            match var.fields {
                                None => {
                                    var_body.push_parsed(format!("Self::{}", var.name))?;
                                }
                                Some(Fields::Tuple(ref f)) if f.len() == 1 => {
                                    var_body.push_parsed(format!("Self::{}(crate::sshwire::SSHDecode::dec(s)?)", var.name))?;
                                }
                            _ => return Err(Error::Custom { error: "SSHDecode currently only implements Unit or single value enum variants. ".into(), span: None})
                            }
                            Ok(())
                        })?;

                    }
                    if let Some(unk) = unknown_arm.take() {
                        match_arm.append(unk);
                    }
                }
                Ok(())
            })?;
            fn_body.push_parsed("; Ok(r)")?;
            Ok(())
        })?;
    Ok(())
}
