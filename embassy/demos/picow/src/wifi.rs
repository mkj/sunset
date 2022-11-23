use embassy_rp::gpio::{Flex, Output};
use embassy_rp::peripherals::{PIN_23, PIN_24, PIN_25, PIN_29};
use embedded_hal_async::spi::{ExclusiveDevice, SpiBusFlush, SpiBusRead, SpiBusWrite};
use embedded_hal_1::spi::ErrorType;
use core::convert::Infallible;
use core::future::Future;

#[embassy_executor::task]
pub(crate) async fn wifi_task(
    runner: cyw43::Runner<'static, Output<'static, PIN_23>, ExclusiveDevice<MySpi, Output<'static, PIN_25>>>,
) -> ! {
    runner.run().await
}

pub(crate) struct MySpi {
    /// SPI clock
    pub clk: Output<'static, PIN_29>,

    /// 4 signals, all in one!!
    /// - SPI MISO
    /// - SPI MOSI
    /// - IRQ
    /// - strap to set to gSPI mode on boot.
    pub dio: Flex<'static, PIN_24>,
}

impl ErrorType for MySpi {
    type Error = Infallible;
}

impl SpiBusFlush for MySpi {
    type FlushFuture<'a> = impl Future<Output = Result<(), Self::Error>>
    where
        Self: 'a;

    fn flush<'a>(&'a mut self) -> Self::FlushFuture<'a> {
        async move { Ok(()) }
    }
}

impl SpiBusRead<u32> for MySpi {
    type ReadFuture<'a> = impl Future<Output = Result<(), Self::Error>> + 'a;

    fn read<'a>(&'a mut self, words: &'a mut [u32]) -> Self::ReadFuture<'a> {
        async move {
            self.dio.set_as_input();
            for word in words {
                let mut w = 0;
                for _ in 0..32 {
                    w = w << 1;

                    // rising edge, sample data
                    if self.dio.is_high() {
                        w |= 0x01;
                    }
                    self.clk.set_high();

                    // falling edge
                    self.clk.set_low();
                }
                *word = w
            }

            Ok(())
        }
    }
}

impl SpiBusWrite<u32> for MySpi {
    type WriteFuture<'a> = impl Future<Output = Result<(), Self::Error>> + 'a;

    fn write<'a>(&'a mut self, words: &'a [u32]) -> Self::WriteFuture<'a> {
        async move {
            self.dio.set_as_output();
            for word in words {
                let mut word = *word;
                for _ in 0..32 {
                    // falling edge, setup data
                    self.clk.set_low();
                    if word & 0x8000_0000 == 0 {
                        self.dio.set_low();
                    } else {
                        self.dio.set_high();
                    }

                    // rising edge
                    self.clk.set_high();

                    word = word << 1;
                }
            }
            self.clk.set_low();

            self.dio.set_as_input();
            Ok(())
        }
    }
}
