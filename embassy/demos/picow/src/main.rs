#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]
#![feature(async_fn_in_trait)]
// #![allow(incomplete_features)]

use defmt::*;
use embassy_executor::Spawner;
use embassy_net::Stack;
use embassy_rp::pio::PioPeripheral;
use {defmt_rtt as _, panic_probe as _};

use static_cell::StaticCell;

use menu::Runner as MenuRunner;
use embedded_io::asynch::Read;
use embassy_sync::signal::Signal;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;

use sunset::*;
use sunset_embassy::SSHServer;

pub(crate) use sunset_demo_embassy_common as demo_common;
use crate::demo_common::singleton;

mod flashconfig;
mod wifi;

use demo_common::{SSHConfig, demo_menu, Shell};

const NUM_LISTENERS: usize = 4;
// +1 for dhcp. referenced directly by wifi_stack() function
pub(crate) const NUM_SOCKETS: usize = NUM_LISTENERS+1;

#[embassy_executor::task]
async fn net_task(stack: &'static Stack<cyw43::NetDriver<'static>>) -> ! {
    stack.run().await
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    info!("Hello World!");

    let mut p = embassy_rp::init(Default::default());

    caprand::setup(&mut p.PIN_10).unwrap();
    getrandom::register_custom_getrandom!(caprand::getrandom);

    let mut flash = embassy_rp::flash::Flash::new(p.FLASH);

    let config = flashconfig::load_or_create(&mut flash).unwrap();

    let ssh_config = &*singleton!(
        config
    );

    let (_, sm, _, _, _) = p.PIO0.split();
    let wifi_net = ssh_config.wifi_net.as_str();
    let wifi_pw = ssh_config.wifi_pw.as_ref().map(|p| p.as_str());

    // spawn the wifi stack
    let stack = wifi::wifi_stack(&spawner, p.PIN_23, p.PIN_24, p.PIN_25, p.PIN_29, p.DMA_CH0, sm,
        wifi_net, wifi_pw).await;
    let stack = &*singleton!(stack);
    unwrap!(spawner.spawn(net_task(&stack)));

    for _ in 0..NUM_LISTENERS {
        spawner.spawn(listener(&stack, &ssh_config)).unwrap();
    }
}

// TODO: pool_size should be NUM_LISTENERS but needs a literal
#[embassy_executor::task(pool_size = 4)]
async fn listener(stack: &'static Stack<cyw43::NetDriver<'static>>, config: &'static SSHConfig) -> ! {
    demo_common::listener::<_, DemoShell>(stack, config).await
}

#[derive(Default)]
struct DemoShell {
    notify: Signal<NoopRawMutex, ChanHandle>,
}

impl Shell for DemoShell {
    fn open_shell(&self, handle: ChanHandle) {
        self.notify.signal(handle);
    }

    async fn run<'f, S: ServBehaviour>(&self, serv: &'f SSHServer<'f, S>) -> Result<()>
    {
        let session = async {
            // wait for a shell to start
            let chan_handle = self.notify.wait().await;
            trace!("got handle");

            let mut stdio = serv.stdio(chan_handle).await?;

            let mut menu_buf = [0u8; 64];
            let menu_out = demo_menu::BufOutput::default();

            let mut menu = MenuRunner::new(&demo_menu::ROOT_MENU, &mut menu_buf, menu_out);

            // bodge
            for c in "help\r\n".bytes() {
                menu.input_byte(c);
            }
            menu.context.flush(&mut stdio).await?;

            loop {
                let mut b = [0u8; 20];
                let lr = stdio.read(&mut b).await?;
                if lr == 0 {
                    break
                }
                let b = &mut b[..lr];
                for c in b.iter() {
                    menu.input_byte(*c);
                    menu.context.flush(&mut stdio).await?;
                }
            }
            Ok(())
        };

        session.await
    }
}
