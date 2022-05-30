use virtue::prelude::*;
use virtue::parse::{EnumBody, StructBody};
use virtue::generate::FnSelfArg;

#[proc_macro_derive(SSHEncode, attributes(sshwire))]
pub fn derive_encode(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    encode_inner(input).unwrap_or_else(|e| e.into_token_stream())
}

fn encode_inner(input: TokenStream) -> Result<TokenStream> {
    let parse = Parse::new(input)?;
    let (mut gen, _att, body) = parse.into_generator();
    match body {
        Body::Struct(body) => {
            encode_struct(&mut gen, body)?;
        }
        Body::Enum(body) => {
            encode_enum(&mut gen, body)?;
        }
    }
    gen.export_to_file("SSHEncode");
    gen.finish()
}

fn encode_struct(gen: &mut Generator, body: StructBody) -> Result<()> {
    gen.impl_for("crate::sshwire::SSHEncode")
        .generate_fn("enc")
        .with_generic_deps("E", ["crate::sshwire::SSHSink"])
        .with_self_arg(FnSelfArg::RefSelf)
        .with_arg("e", "&mut E")
        .with_return_type("Result<()>")
        .body(|fn_body| {
            for f in body.fields.names() {
                // TODO attributes here
                fn_body.push_parsed(format!("crate::sshwire::SSHEncode::enc(&self.{f}, e)?;"))?;
            }
            fn_body.push_parsed("Ok(())")?;
            Ok(())
        })?;
    Ok(())
}

fn encode_enum(gen: &mut Generator, body: EnumBody) -> Result<()> {
    if body.variants.is_empty() {
        return Ok(())
    }

    gen.impl_for("crate::sshwire::SSHEncode")
        .generate_fn("enc")
        .with_generic_deps("E", ["crate::sshwire::SSHSink"])
        .with_self_arg(FnSelfArg::RefSelf)
        .with_arg("e", "&mut E")
        .with_return_type("Result<()>")
        .body(|fn_body| {
            fn_body.ident_str("match");
            fn_body.puncts("*");
            fn_body.ident_str("self");
            fn_body.group(Delimiter::Brace, |match_arm| {
                for var in body.variants {
                    match_arm.ident_str("Self");
                    match_arm.puncts("::");
                    match_arm.ident(var.name.clone());

                    let mut rhs = StreamBuilder::new();
                    match var.fields {
                        Fields::Unit => {
                            // nothing to do
                        }
                        Fields::Tuple(ref f) if f.len() == 1 => {
                            match_arm.group(Delimiter::Parenthesis, |item| {
                                item.ident_str("ref");
                                item.ident_str("i");
                                Ok(())
                            })?;
                            rhs.push_parsed(format!("crate::sshwire::SSHEncode::enc(i, e)?;"))?;

                        }
                        _ => return Err(Error::Custom { error: "SSHEncode currently only implements Unit or single value enum variants. ".into(), span: None})
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
    Ok(())
}
