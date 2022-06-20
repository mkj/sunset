This documents various design decisions, also to be read as _lessons learned_.
At the time you read this they may, or may not, still be relevant.
Apologies if I seem overly critical of any projects - I have huge respect for
all of the dependencies I've tried.

## Error type

Snafu seems to do the job for an error type.

Initially the `Error` type had two 35 byte `UnknownName`s in one of the variants.
Removing that reduced the arm thumb binary size by 16kB! The reason appears to be that
when the error variant of `Result` is larger than the `Ok` item, it can't be used
to construct a struct in-place (it has to write to temporary larger stack space,
then copy the item out). That matters a lot for the `sshwire` deserialisation
that recursively creates lots of structs.

`.trap()` is there as an alternative to `.unwrap()` - if a server handles multiple connections
you don't want them all going away panicking if there's some un-thought-of edge case.
Each call to `.trap()` seems on the order of perhaps 100 bytes larger than a plain `panic!()` -
perhaps there should be a feature to just panic. In debug builds it panics too so it's quick
to get a backtrace.

## Serialisation/deserialisation

Previously the code used `serde` with a custom `Serializer`/`Deserializer`. That worked
fine for serializing and `derive(Deserialize)`, but deserializing enums was a pain.
For types like `packets::ChannelRequest`
the deserializer had to stash the channel request type string from the `ChannelRequest` struct somewhere,
then use that later when deserialising the `ChannelReqType` enum. Other response packets like number 60 `Userauth60`
mean completely different things depending on the previous request, but that state is hard to pass through
the deserializer.

[`serde_state`](https://docs.rs/serde_state/latest/serde_state/) solves some of it, but was still a bit awkward,
and didn't work well with manually written `Deserialize` implementations.

serde is fairly flexible design,
but for our purposes we can use something much simpler - the packet format is not self describing
(in most parts), we just take bytes off the wire exactly as we expect them.

Eventually I gave up fighting and wrote a new `sshwire_derive` with
[virtue](https://github.com/bincode-org/virtue) crate. That is about 10kB smaller
(arm thumb) and easier to customise as required. For example `UnknownName` has a simple attribute to indicate
that's the variant that should store an unmatched string.

It was easier than I expected - the virtue syntax seems a bit verbose but feels more intuitive than
`syn` or `quote` crates which are the alternative. I think this is because it's still written in
normal Rust, not a new macro language to learn.

## Ring vs RustCrypto

Initially the code was written using `ring`, mainly because it already had
[`chacha20_poly1305_openssh`](https://docs.rs/ring/latest/ring/aead/chacha20_poly1305_openssh/index.html).
That worked great until I tried to build for a `thumbv7em` platform. Some of the code wouldn't build
(ARM assembly issues?, possibly fixable),
but the bigger problem is there's no way to insert a custom random number generator.

Instead switching to RustCrypto crates worked fairly easily, though perhaps a bit messier having
to deal with `GenericArray` and `DynamicDigest` and types like that. At the time of writing `curve25519-dalek` etc
are a bit behind on dependencies which is messy, but I assume that will sort itself out.

## `Behaviour`

At some points in packet handling some custom behaviour from the application is required. For example
"is this hostkey valid?", "is this user's password correct?". Those need an immediate response,
so `.await` fits well.

The problem is that `async_trait` requires `Box`, won't work on `no_std`. The `Behaviour` struct has a `cfg` to switch
between async and non-async traits, hiding that from the main code. Eventually `async fn` [should work OK](https://github.com/rust-lang/rust/issues/91611) in static traits on `no_std`, and then it can be unified.

## Async

The majority of packet dispatch handling isn't async, it just returns Ready straight away. Becaues of that we just have a Tokio `Mutex` which occassionally
holds the mutex across the `.await` boundary - it should seldom be contended.
