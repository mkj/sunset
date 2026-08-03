use core::cell::RefCell;
use core::future::poll_fn;
use core::task::{Poll, Waker};

use crate::error::SftpError;
use crate::proto::{
    self, InitVersionClient, InitVersionLowest, LStat, MAX_REQUEST_LEN, ReqId,
    SFTP_VERSION, SftpPacket, Stat, StatusCode,
};
use crate::server::DirReadHeaderReply;
use crate::sftperror::SftpResult;
use crate::sftphandler::sftpoutputchannelhandler::SftpOutputProducer;
use crate::sftpserver::{DirHandle, FileHandle, ReadHeaderReply, SftpServer};
use crate::sftpserver::{FileOrDirHandle, decode_opaque_handle};
use crate::sftpsource::{SftpDecoded, SftpSource};

use sunset::error::TrapBug;

use embassy_futures::select::{Either, select};
use embedded_io_async::{Read, Write};
#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

/// FSM for handling SFTP requests during [`SftpHandler::process`].
#[derive(Debug, PartialEq, Eq)]
enum HandlerState {
    /// Processing first packet, Init or Version.
    First,
    /// Processing standard packets.
    Normal,
    /// A Write request.
    ///
    /// Write request data is provided directly to the `SftpServer`,
    /// not included in the packet struct.
    ProcessWriteRequest {
        req_id: ReqId,
        handle: FileHandle,
        offset: u64,
        remaining: usize,
    },
    /// Used to drain input in cases where there is still
    /// data to be process but no longer required
    Drain { remaining: usize },
}

/// Size of the input BBQueue
///
/// The queue is used to avoid a deadlock during SFTP Read where process_packet()
/// needs to send response data, but has no SSH send window available.
/// The window adjust has been sent by the SFTP client, but it
/// hasn't yet been seen/processed by the Sunset core because the
/// current SFTP packet processing hasn't completed.
///
/// By adding a queue, the packets being processed can be drained allowing
/// sunset core process the send window adjust, allowing responses to be sent.
///
/// OpenSSH sftp client keeps 64 pipelined 32768 byte read requests.
/// It sends a window adjust every 3*32768 bytes received,
/// so we allow to receive a buffer of 5 read requests for some leeway
/// (also for BBQueue wraparound behaviour).
/// 30 is the size of a Read SFTP packet including all headers.
/// There may be other other pathological cases, in theory up to
/// TrafIn.buf.len() bytes might need to be buffered by SFTP.
///
/// The deadlock can be reproduced with
/// demo/sftp/std/testing/test_get_file_long.sh
const INPUT_BUF: usize = 30 * 5;

/// A SFTP server implementation.
///
/// Parameter `RESP_BUF` sizes an output buffer to send responses.
/// Must be sufficiently to create responses such as file entries
/// (size will depend on maximum file length).
/// 512 would be a typical small buffer.
///
/// `REQ_BUF` is the input buffer that must be able to hold
/// an input request.
///
/// These buffer sizes don't include read/write file data, which is
/// handled separately.
///
/// Default values can be used with [`SftpServerHandler::new_default_buffers()`].
/// `SftpServerHandler` has const constructors so it can be placed in static storage.
///
/// Application specific handling is provided as a [`SftpServer`] argument
/// to [`SftpServerHandler::run`].
pub struct SftpServerHandler<const REQ_BUF: usize, const RESP_BUF: usize> {
    /// Queue to avoid deadlock. See INPUT_BUF docs.
    in_queue: SFTPBBQueue<INPUT_BUF>,

    /// Buffer for one input packet
    in_buf: [u8; REQ_BUF],
    /// Buffer for one output packet
    out_buf: [u8; RESP_BUF],
}

// TODO is MAX_REQUEST_LEN appropriate for responses?
impl SftpServerHandler<MAX_REQUEST_LEN, MAX_REQUEST_LEN> {
    /// Create a new `SftpServerHandler` with default buffers.
    ///
    /// Both request and response buffers will be sized as [`MAX_REQUEST_LEN`].
    pub const fn new_default_buffers() -> Self {
        Self::new()
    }
}

impl Default for SftpServerHandler<MAX_REQUEST_LEN, MAX_REQUEST_LEN> {
    /// Calls [`SftpServerHandler::new_default_buffers`].
    fn default() -> Self {
        Self::new_default_buffers()
    }
}

impl<const REQ_BUF: usize, const RESP_BUF: usize>
    SftpServerHandler<REQ_BUF, RESP_BUF>
{
    /// Create a new `SftpServerHandler`.
    ///
    /// [`SftpServerHandler::new_default_buffers()`] can be used
    /// for default sized buffers.
    pub const fn new() -> Self {
        Self { in_queue: SFTPBBQueue::new(), in_buf: [0; _], out_buf: [0; _] }
    }

    /// Runs the SFTP server loop to completion.
    ///
    /// Takes an [`embedded_io_async::Read`] and [`embedded_io_async::Write`].
    /// Processes all the requests from `chan_in` until an EOF is received.
    ///
    /// Will delegate requests to an [`SftpServer`]
    /// implemented by the library user taking into account the local system details.
    ///
    /// `run` may only be called once for each SFTP session, any failures
    /// are fatal. It is OK to reuse a `SftpServerHandler` with a new
    /// SFTP session.
    pub async fn run(
        &mut self,
        file_server: &mut impl SftpServer,
        chan_in: impl Read,
        chan_out: impl Write,
    ) -> SftpResult<()> {
        // Reset state in case of reuse.
        // in_buf/out_buf content shouldn't matter, but zeroing them
        // avoids some risk from bugs.
        *self = Self::new();

        Handler::new(file_server)
            .process_loop(
                chan_in,
                chan_out,
                &self.in_queue,
                &mut self.in_buf,
                &mut self.out_buf,
            )
            .await
    }
}

/// Inner structure, without storage.
struct Handler<'a, S>
where
    S: SftpServer,
{
    /// Holds the internal state if the SFTP handle
    state: HandlerState,

    /// The local SFTP File server implementing the basic SFTP requests
    /// defined by [`crate::sftpserver::SftpServer`]
    file_server: &'a mut S,
}

impl<'a, S> Handler<'a, S>
where
    S: SftpServer,
{
    /// Creates a new instance of the structure.
    ///
    /// Requires:
    ///
    /// - `file_server` (implementing [`crate::sftpserver::SftpServer`] ): to execute
    ///   the request in the local system
    /// - `request_buffer`: used to deal with fragmented
    ///   packets during [`SftpHandler::process_loop`]
    fn new(file_server: &'a mut S) -> Self {
        Handler { file_server, state: HandlerState::First }
    }

    /// Runs the SFTP server loop.
    ///
    /// Takes an [`embedded_io_async::Read`] and [`embedded_io_async::Write`].
    /// Processes all the request from `chan_in` until an EOF is received.
    async fn process_loop(
        &mut self,
        mut chan_in: impl Read,
        mut chan_out: impl Write,
        in_queue: &SFTPBBQueue<INPUT_BUF>,
        in_buf: &mut [u8],
        out_buf: &mut [u8],
    ) -> SftpResult<()> {
        // A single request should be adequate for progress.
        let mut output_producer = SftpOutputProducer::new(&mut chan_out, out_buf);

        // Docs for `INPUT_BUF` describe the queue's purpose.
        // in_buf may not be shared between futures.

        let read_loop = async {
            let prod = in_queue.stream_producer();
            loop {
                let mut input = prod.wait_grant_max_remaining(usize::MAX).await;
                trace!("SFTP: About to read bytes from SSH Channel");

                let lr = chan_in
                    .read(&mut input)
                    .await
                    .map_err(SftpError::from_embedded_io)?;

                debug!("SFTP <---- received: {:?} bytes", lr);
                trace!("SFTP <---- received: {:?}", &input[0..lr]);
                if lr == 0 {
                    debug!("client disconnected");
                    return Err(SftpError::Disconnected);
                }

                input.commit(lr);
            }
            #[allow(unreachable_code)]
            SftpResult::Ok(())
        };

        let process = self.process(in_queue, in_buf, &mut output_producer);

        // TODO: on read_loop error, should wait for in_buf to drain,
        // with wait_grant_exact(IN_BUF), then can cancel
        // the handler. (Or in future have a nicer cleanup for the
        // SftpServer perhaps).
        //
        // Or perhaps it doesn't matter given SFTP is request/response,
        // and a peer won't disconnect until it's received all the
        // responses its waiting for...

        match select(read_loop, process).await {
            Either::First(r) => {
                error!("Read returned: {:?}", r);
                r
            }
            Either::Second(r) => {
                error!("Processing returned: {:?}", r);
                r
            }
        }
    }

    async fn process_first_packet<W>(
        &mut self,
        sftp_packet: SftpPacket<'_>,
        output_producer: &mut SftpOutputProducer<'_, W>,
    ) -> SftpResult<()>
    where
        W: Write,
    {
        self.state = HandlerState::Normal;

        match sftp_packet {
            SftpPacket::Init(InitVersionClient { version: SFTP_VERSION }) => {
                output_producer
                    .send_packet(&SftpPacket::Version(InitVersionLowest {
                        version: SFTP_VERSION,
                    }))
                    .await?;
                Ok(())
            }
            SftpPacket::Init(InitVersionClient { version }) => {
                error!(
                    "Incompatible SFTP Version: {version:?} expected {SFTP_VERSION:?}"
                );
                Err(SftpError::NotSupported)
            }
            _ => {
                error!("Wrong SFTP Packet before Init");
                Err(SftpError::NotInitialized)
            }
        }
    }

    async fn process_packet<W>(
        &mut self,
        sftp_packet: SftpPacket<'_>,
        output_producer: &mut SftpOutputProducer<'_, W>,
    ) -> SftpResult<()>
    where
        W: Write,
    {
        if !sftp_packet.sftp_num().is_request() {
            // SSH_FX_BAD_MESSAGE response would also be OK, but getting
            // the req_id is awkward and it shouldn't happen.
            error!("Unexpected SftpPacket: {:?}", sftp_packet.sftp_num());
            return Err(sunset::error::SSHProto.build().into());
        }

        match sftp_packet {
            SftpPacket::Read(req_id, ref read) => {
                debug!("Read request: {:?}", sftp_packet);

                let reply = ReadHeaderReply::new(req_id, output_producer);

                let res = match FileHandle::try_from(read.handle) {
                    Ok(h) => {
                        self.file_server.read(h, read.offset, read.len, reply).await
                    }
                    Err(e) => Err(e.into()),
                };

                if let Err(error) = res {
                    error!("Error reading data: {:?}", error);
                    if let SftpError::FileServerError(status) = error {
                        output_producer.send_status(req_id, status, "").await?;
                    } else {
                        output_producer
                            .send_status(
                                req_id,
                                StatusCode::SSH_FX_FAILURE,
                                "Read failed",
                            )
                            .await?;
                    }
                };
            }
            SftpPacket::LStat(req_id, LStat { file_path: path }) => {
                match self.file_server.attrs(false, path.to_str()?).await {
                    Ok(attrs) => {
                        debug!("List stats for {} is {:?}", path, attrs);

                        output_producer
                            .send_packet(&SftpPacket::Attrs(req_id, attrs))
                            .await?;
                    }
                    Err(status) => {
                        error!("Error listing stats for {}: {:?}", path, status);
                        output_producer
                            .send_status(req_id, status, "Could not list attributes")
                            .await?;
                    }
                };
            }
            SftpPacket::Stat(req_id, Stat { file_path: path }) => {
                match self.file_server.attrs(true, path.to_str()?).await {
                    Ok(attrs) => {
                        debug!("List stats for {} is {:?}", path, attrs);

                        output_producer
                            .send_packet(&SftpPacket::Attrs(req_id, attrs))
                            .await?;
                    }
                    Err(status) => {
                        error!("Error listing stats for {}: {:?}", path, status);
                        output_producer
                            .send_status(req_id, status, "Could not list attributes")
                            .await?;
                    }
                };
            }
            SftpPacket::ReadDir(req_id, read_dir) => {
                let dir_read_header_reply =
                    DirReadHeaderReply::new(req_id, output_producer);

                let res = match DirHandle::try_from(read_dir.handle) {
                    Ok(h) => {
                        self.file_server.readdir(h, dir_read_header_reply).await
                    }
                    Err(e) => Err(e),
                };

                if let Err(status) = res {
                    error!("Open failed: {:?}", status);

                    output_producer
                        .send_status(req_id, status, "Error Reading Directory")
                        .await?;
                };
            }
            SftpPacket::OpenDir(req_id, open_dir) => {
                match self.file_server.opendir(open_dir.dirname.as_str()?).await {
                    Ok(dirh) => {
                        let mut buf = DirHandle::buffer();
                        let handle = dirh.encode(&mut buf);
                        let response =
                            SftpPacket::Handle(req_id, proto::Handle { handle });
                        output_producer.send_packet(&response).await?;
                    }
                    Err(status_code) => {
                        error!("Open failed: {:?}", status_code);
                        output_producer
                            .send_status(req_id, StatusCode::SSH_FX_FAILURE, "")
                            .await?;
                    }
                };
            }
            SftpPacket::Close(req_id, close) => {
                let res = {
                    match decode_opaque_handle(close.handle) {
                        Ok(FileOrDirHandle::File(h)) => {
                            self.file_server.close(h).await
                        }
                        Ok(FileOrDirHandle::Dir(h)) => {
                            self.file_server.closedir(h).await
                        }
                        Err(e) => Err(e),
                    }
                };

                match res {
                    Ok(_) => {
                        output_producer
                            .send_status(req_id, StatusCode::SSH_FX_OK, "")
                            .await?;
                    }
                    Err(e) => {
                        error!("SFTP Close thrown: {:?}", e);
                        output_producer
                            .send_status(
                                req_id,
                                StatusCode::SSH_FX_FAILURE,
                                "Could not Close the handle",
                            )
                            .await?;
                    }
                }
            }
            SftpPacket::Write(req_id, write) => {
                debug!("Got write: {:?}", write);

                match FileHandle::try_from(write.handle) {
                    Ok(handle) => {
                        self.state = HandlerState::ProcessWriteRequest {
                            req_id,
                            handle,
                            offset: write.offset,
                            remaining: write.data_len as usize,
                        };
                    }
                    Err(_) => {
                        output_producer
                            .send_status(
                                req_id,
                                StatusCode::SSH_FX_FAILURE,
                                "Bad handle",
                            )
                            .await?;
                    }
                };
            }
            SftpPacket::Open(req_id, open) => {
                match self
                    .file_server
                    .open(open.filename.as_str()?, &open.pflags)
                    .await
                {
                    Ok(fh) => {
                        let mut buf = FileHandle::buffer();
                        let handle = fh.encode(&mut buf);
                        let response =
                            SftpPacket::Handle(req_id, proto::Handle { handle });
                        output_producer.send_packet(&response).await?;
                    }
                    Err(status_code) => {
                        error!("Open failed: {:?}", status_code);
                        output_producer
                            .send_status(req_id, StatusCode::SSH_FX_FAILURE, "")
                            .await?;
                    }
                };
            }
            SftpPacket::PathInfo(req_id, path_info) => {
                match self.file_server.realpath(path_info.path.to_str()?).await {
                    Ok(name_entry) => {
                        let dir_read_header_reply =
                            DirReadHeaderReply::new(req_id, output_producer);
                        let encoded_len =
                            crate::sftpserver::helpers::get_name_entry_len(
                                &name_entry,
                            )?;
                        debug!("PathInfo encoded length: {:?}", encoded_len);
                        trace!("PathInfo Response content: {:?}", encoded_len);
                        let dir_read_data_reply = dir_read_header_reply
                            .send_header(encoded_len, 1)
                            .await?;
                        dir_read_data_reply
                            .send_data(|mut sender| async move {
                                sender.send_item(&name_entry).await?;
                                sender.completed().trap().map_err(|e| e.into())
                            })
                            .await?;
                    }
                    Err(code) => {
                        output_producer.send_status(req_id, code, "").await?;
                    }
                }
            }
            SftpPacket::Init(..)
            | SftpPacket::Version(..)
            | SftpPacket::Status(..)
            | SftpPacket::Handle(..)
            | SftpPacket::Data(..)
            | SftpPacket::Name(..)
            | SftpPacket::Attrs(..) => {
                // Should have been caught by is_request() above.
                sunset::Error::bug()?;
            }
        }
        Ok(())
    }

    /// Process write data.
    ///
    /// Must be called with `HandlerState::ProcessWriteRequest`
    async fn process_write<W>(
        &mut self,
        input: &SFTPBBQueue<INPUT_BUF>,
        output_producer: &mut SftpOutputProducer<'_, W>,
    ) -> SftpResult<()>
    where
        W: Write,
    {
        let HandlerState::ProcessWriteRequest {
            req_id,
            handle,
            mut offset,
            mut remaining,
        } = self.state
        else {
            sunset::Error::bug()?
        };
        self.state = HandlerState::Normal;

        let cons = input.stream_consumer();

        while remaining > 0 {
            // Read from input channel
            let inp = cons.wait_read().await;
            let data = &inp[..remaining.min(inp.len())];

            if let Err(e) = self.file_server.write(handle, offset, data).await {
                error!("SFTP write thrown: {:?}", e);
                output_producer
                    .send_status(req_id, StatusCode::SSH_FX_FAILURE, "error writing")
                    .await?;
                self.state = HandlerState::Drain { remaining };
                return Ok(());
            }

            offset += data.len() as u64;
            remaining -= data.len();
            let d = data.len();
            inp.release(d);
        }

        output_producer.send_status(req_id, StatusCode::SSH_FX_OK, "").await
    }

    async fn drain(
        &mut self,
        input: &SFTPBBQueue<INPUT_BUF>,
        mut len: usize,
    ) -> SftpResult<()> {
        let cons = input.stream_consumer();
        while len > 0 {
            let inp = cons.wait_read().await;
            let l = inp.len().min(len);
            inp.release(l);
            len -= l;
        }

        Ok(())
    }

    /// - Decodes the buffer_in request
    /// - Process the request delegating
    ///   operations to a [`SftpServer`] implementation
    /// - Serializes an answer in `output_producer`
    ///
    /// Returns the amount of data consumed.
    async fn process<W>(
        &mut self,
        input: &SFTPBBQueue<INPUT_BUF>,
        in_buf: &mut [u8],
        output_producer: &mut SftpOutputProducer<'_, W>,
    ) -> SftpResult<()>
    where
        W: Write,
    {
        loop {
            match self.state {
                HandlerState::First | HandlerState::Normal => {
                    // TODO error handling
                    let first = matches!(self.state, HandlerState::First);
                    self.process_one(input, output_producer, in_buf, first).await?;
                }
                HandlerState::ProcessWriteRequest { .. } => {
                    self.process_write(input, output_producer).await?;
                }
                HandlerState::Drain { remaining } => {
                    self.drain(input, remaining).await?;
                }
            }
        }
    }

    async fn process_one<W>(
        &mut self,
        input: &SFTPBBQueue<INPUT_BUF>,
        output_producer: &mut SftpOutputProducer<'_, W>,
        in_buf: &mut [u8],
        first: bool,
    ) -> SftpResult<()>
    where
        W: Write,
    {
        let mut source = SftpSource::empty(in_buf);
        match source.fill(input).await {
            SftpDecoded::Packet(pkt) => {
                if first {
                    self.process_first_packet(pkt, output_producer).await?;
                } else {
                    self.process_packet(pkt, output_producer).await?;
                }
                output_producer.flush().await?;
            }
            SftpDecoded::UnknownPacket { req_id, number: _ } => {
                output_producer
                    .send_status(req_id, StatusCode::SSH_FX_OP_UNSUPPORTED, "")
                    .await?;
            }
            SftpDecoded::BadMessage { req_id } => {
                output_producer
                    .send_status(req_id, StatusCode::SSH_FX_BAD_MESSAGE, "")
                    .await?;
            }
            SftpDecoded::Failure { req_id } => {
                output_producer
                    .send_status(req_id, StatusCode::SSH_FX_FAILURE, "")
                    .await?;
            }
            SftpDecoded::FillError { error } => return Err(error),
        }

        Ok(())
    }
}

// Platforms like thumbv6m-none-eabi can't atomics, so instead
// use critical-section.
// cfg_select format varies with rust nightly
#[rustfmt::skip]
type SFTPCoord =
    cfg_select! {
        target_has_atomic = "ptr" => bbqueue::traits::coordination::cas::AtomicCoord,
        _ => bbqueue::traits::coordination::cs::CsCoord,
    };

/// An async bbqueue with inline storage
///
/// This must only be used within a single `Future`, so it
/// can use a simple `Notifier`.
pub type SFTPBBQueue<const N: usize> =
    bbqueue::BBQueue<bbqueue::traits::storage::Inline<N>, SFTPCoord, OneFutNotifier>;

pub struct OneFutNotifier {
    /// Only used within a single future, so one `Waker` is enough.
    waker: RefCell<Option<Waker>>,
}

impl bbqueue::export::ConstInit for OneFutNotifier {
    const INIT: Self = OneFutNotifier { waker: RefCell::new(None) };
}

impl bbqueue::traits::notifier::Notifier for OneFutNotifier {
    fn wake_one_consumer(&self) {
        if let Some(w) = self.waker.take() {
            w.wake_by_ref()
        }
    }

    fn wake_one_producer(&self) {
        self.wake_one_consumer();
    }
}

impl bbqueue::traits::notifier::AsyncNotifier for OneFutNotifier {
    async fn wait_for_not_empty<T, F: FnMut() -> Option<T>>(&self, mut f: F) -> T {
        poll_fn(|cx| match f() {
            Some(t) => Poll::Ready(t),
            None => {
                if !self
                    .waker
                    .borrow()
                    .as_ref()
                    .is_some_and(|w| w.will_wake(cx.waker()))
                {
                    self.waker.replace(Some(cx.waker().clone()));
                }
                Poll::Pending
            }
        })
        .await
    }
    async fn wait_for_not_full<T, F: FnMut() -> Option<T>>(&self, f: F) -> T {
        self.wait_for_not_empty(f).await
    }
}
