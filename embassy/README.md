# Toolchain

Embassy requires Rust nightly, often with a specific version. [`rust-toolchain.toml`] records a known-good version.

# Demos

[`demos/`] has some examples. These are separate crates since they have fairly distinct dependencies.

## `picow`

Running on a Raspberry Pi Pico W.

Requires a capacitor soldered between a GPIO pin and gnd, 0.1 to 1 nF is suitable, this example uses GPIO Pin 10.
This is used for random number generation - it is somewhat experimental and should have more analysis
of the RNG quality before use in real applications.

## `std`

Running on the host system, useful for development and debugging.
The network stack is smoltcp with a `tap` device. Based on Embassy's `examples/std/src/tuntap.rs`, it needs
local network setup something like

```sh
sudo ip tuntap add name tap0 mode tap user $USER
sudo ip link set tap0 up
sudo ip addr add 10.9.0.1/16 dev tap0
```
