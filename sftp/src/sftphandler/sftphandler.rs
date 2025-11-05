use super::PartialWriteRequestTracker;

use crate::error::SftpError;
use crate::handles::OpaqueFileHandle;
use crate::proto::{
    self, InitVersionLowest, ReqId, SFTP_MINIMUM_PACKET_LEN, SFTP_VERSION, SftpNum,
    SftpPacket, StatusCode,
};
use crate::requestholder::{RequestHolder, RequestHolderError};
use crate::server::DirReply;
use crate::sftperror::SftpResult;
use crate::sftphandler::sftpoutputchannelwrapper::SftpOutputChannelWrapper;
use crate::sftpserver::SftpServer;
use crate::sftpsource::SftpSource;

use sunset::Error as SunsetError;
use sunset::sshwire::{SSHSource, WireError};
use sunset_async::ChanInOut;

use core::u32;
use embedded_io_async::Read;
#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

/// FSM for handling sftp requests during [`SftpHandler::process`]
#[derive(Default, Debug, PartialEq, Eq)]
enum SftpHandleState {
    /// The handle is not initialized
    #[default]
    Initializing,
    /// The handle is ready to process requests
    Idle,
    /// The request is fragmented and needs special handling
    Fragmented(FragmentedRequestState),
}

/// FSM subset to handle fragmented request as part of [`SftpHandleState`]
#[derive(Debug, PartialEq, Eq)]
enum FragmentedRequestState {
    /// A request that is clipped needs to be process. It cannot be decoded
    /// and more bytes are needed
    ProcessingClippedRequest,
    /// A request, with a length over the incoming buffer capacity is being
    /// processed.
    ///
    /// E.g. a write request with size exceeding the
    /// buffer size: Processing this request will require to be split
    /// into multiple write actions
    ProcessingLongRequest,
}

// // TODO Generalize this to allow other request types
// /// Used to keep record of a long SFTP Write request that does not fit in
// /// receiving buffer and requires processing in batches
// #[derive(Debug)]
// pub struct PartialWriteRequestTracker<T: OpaqueFileHandle> {
//     req_id: ReqId,
//     opaque_handle: T,
//     remain_data_len: u32,
//     remain_data_offset: u64,
// }

// impl<T: OpaqueFileHandle> PartialWriteRequestTracker<T> {
//     /// Creates a new [`PartialWriteRequestTracker`]
//     pub fn new(
//         req_id: ReqId,
//         opaque_handle: T,
//         remain_data_len: u32,
//         remain_data_offset: u64,
//     ) -> WireResult<Self> {
//         Ok(PartialWriteRequestTracker {
//             req_id,
//             opaque_handle: opaque_handle,
//             remain_data_len,
//             remain_data_offset,
//         })
//     }
//     /// Returns the opaque file handle associated with the request
//     /// tracked
//     pub fn get_opaque_file_handle(&self) -> T {
//         self.opaque_handle.clone()
//     }
// }

/// Process the raw buffers in and out from a subsystem channel decoding
/// request and encoding responses
///
/// It will delegate request to an [`crate::sftpserver::SftpServer`]
/// implemented by the library
/// user taking into account the local system details.
pub struct SftpHandler<'a, T, S>
where
    T: OpaqueFileHandle,
    S: SftpServer<'a, T>,
{
    /// Holds the internal state if the SFTP handle
    state: SftpHandleState,

    /// The local SFTP File server implementing the basic SFTP requests
    /// defined by [`crate::sftpserver::SftpServer`]
    file_server: &'a mut S,

    /// Use to process SFTP Write packets that have been received
    /// partially and the remaining is expected in successive buffers  
    partial_write_request_tracker: Option<PartialWriteRequestTracker<T>>,

    incomplete_request_holder: RequestHolder<'a>,
}

impl<'a, T, S> SftpHandler<'a, T, S>
where
    T: OpaqueFileHandle,
    S: SftpServer<'a, T>,
{
    /// Creates a new instance of the structure.
    ///
    /// Requires:
    ///
    /// - `file_server` (implementing [`crate::sftpserver::SftpServer`] ): to execute
    /// the request in the local system
    /// - `incomplete_request_buffer`: used to deal with fragmented
    /// packets during [`SftpHandler::process`]
    pub fn new(
        file_server: &'a mut S,
        incomplete_request_buffer: &'a mut [u8],
    ) -> Self {
        SftpHandler {
            file_server,
            partial_write_request_tracker: None,
            state: SftpHandleState::default(),
            incomplete_request_holder: RequestHolder::new(incomplete_request_buffer),
        }
    }

    /// WIP: A version of process that takes a chan_out to write the data
    ///
    /// Maintaining an internal status:
    ///
    /// - Decodes the buffer_in request
    /// - Process the request delegating
    /// operations to a [`SftpHandler::process`] implementation
    /// - Serializes an answer in buffer_out
    ///
    /// **Returns**: A result containing the number of bytes used in
    /// `buffer_out`
    async fn process<'g>(
        &mut self,
        buffer_in: &[u8],
        output_wrapper: &mut SftpOutputChannelWrapper<'a, 'g>,
    ) -> SftpResult<()> {
        let in_len = buffer_in.len();
        let mut buffer_in_lower_index_bracket = 0;

        trace!("Received {:} bytes to process", in_len);

        if !matches!(self.state, SftpHandleState::Fragmented(_))
            & in_len.lt(&SFTP_MINIMUM_PACKET_LEN)
        {
            return Err(WireError::PacketWrong.into());
        }

        while buffer_in_lower_index_bracket < in_len {
            debug!(
                "Buffer In Lower index bracket: {}",
                buffer_in_lower_index_bracket
            );
            debug!(
                "<=======================[ SFTP Process State: {:?} ]=======================>",
                self.state
            );

            match &self.state {
                // There is a fragmented request in process of processing
                SftpHandleState::Fragmented(fragment_case) => {
                    match fragment_case {
                        FragmentedRequestState::ProcessingClippedRequest => {
                            if let Err(e) = self
                                .incomplete_request_holder
                                .try_append_for_valid_request(
                                    &buffer_in[buffer_in_lower_index_bracket..],
                                )
                            {
                                match e {
                                    RequestHolderError::RanOut => {
                                        warn!(
                                            "There was not enough bytes in the buffer_in. \
                                            We will continue adding bytes"
                                        );
                                        buffer_in_lower_index_bracket += self
                                            .incomplete_request_holder
                                            .appended();
                                        continue;
                                    }
                                    RequestHolderError::WireError(
                                        WireError::RanOut,
                                    ) => {
                                        warn!(
                                            "WIRE ERROR: There was not enough bytes in the buffer_in. \
                                            We will continue adding bytes"
                                        );
                                        buffer_in_lower_index_bracket += self
                                            .incomplete_request_holder
                                            .appended();
                                        continue;
                                    }
                                    RequestHolderError::NoRoom => {
                                    warn!(
                                        "The request holder is full but the request in is incomplete. \
                                                We will try to decode it"
                                    );
                                }

                                    _ => {
                                        error!(
                                            "Unhandled error completing incomplete request {:?}",
                                            e,
                                        );
                                        return Err(SunsetError::Bug.into());
                                    }
                                }
                            } else {
                                debug!(
                                    "Incomplete request holder completed the request!"
                                );
                            }

                            let used = self.incomplete_request_holder.appended();
                            buffer_in_lower_index_bracket += used;

                            let mut source = SftpSource::new(
                                &self.incomplete_request_holder.try_get_ref()?,
                            );
                            trace!("Internal Source Content: {:?}", source);

                            match SftpPacket::decode_request(&mut source) {
                                Ok(request) => {
                                    Self::handle_general_request(
                                        &mut self.file_server,
                                        output_wrapper,
                                        request,
                                    )
                                    .await?;
                                    self.incomplete_request_holder.reset();
                                    self.state = SftpHandleState::Idle;
                                }
                                Err(e) => match e {
                                    WireError::RanOut => match Self::handle_ran_out(
                                        &mut self.file_server,
                                        output_wrapper,
                                        &mut source,
                                    )
                                    .await
                                    {
                                        Ok(holder) => {
                                            self.partial_write_request_tracker =
                                                Some(holder);
                                            self.incomplete_request_holder.reset();
                                            self.state = SftpHandleState::Fragmented(FragmentedRequestState::ProcessingLongRequest);
                                        }
                                        Err(e) => match e {
                                            _ => {
                                                error!(
                                                    "handle_ran_out finished with error: {:?}",
                                                    e
                                                );
                                                return Err(SunsetError::Bug.into());
                                            }
                                        },
                                    },
                                    WireError::NoRoom => {
                                        error!("Not enough space to fit the request")
                                    }
                                    _ => {
                                        error!(
                                            "Unhandled error decoding assembled packet: {:?}",
                                            e
                                        );
                                        return Err(WireError::PacketWrong.into());
                                    }
                                },
                            }
                        }
                        FragmentedRequestState::ProcessingLongRequest => {
                            let mut source = SftpSource::new(
                                &buffer_in[buffer_in_lower_index_bracket..],
                            );
                            trace!("Source content: {:?}", source);

                            let mut write_tracker = if let Some(wt) =
                                self.partial_write_request_tracker.take()
                            {
                                wt
                            } else {
                                error!(
                                    "BUG: FragmentedRequestState::ProcessingLongRequest cannot take the write tracker"
                                );
                                return Err(SunsetError::Bug.into());
                            };

                            let opaque_handle =
                                write_tracker.get_opaque_file_handle();

                            let usable_data = source
                                .remaining()
                                .min(write_tracker.get_remain_data_len() as usize);

                            let data_segment = // Fails!!
                                            source.dec_as_binstring(usable_data)?;

                            let data_segment_len = u32::try_from(
                                data_segment.0.len(),
                            )
                            .map_err(|e| {
                                error!("Error casting data segment len to u32: {e}");
                                SunsetError::Bug
                            })?;
                            let current_write_offset =
                                write_tracker.get_remain_data_offset();
                            write_tracker.update_remaining_after_partial_write(
                                data_segment_len,
                            );

                            debug!(
                                "Processing successive chunks of a long write packet. \
                                Writing : opaque_handle = {:?}, write_offset = {:?}, \
                                data_segment = {:?}, data remaining = {:?}",
                                opaque_handle,
                                current_write_offset,
                                data_segment,
                                write_tracker.get_remain_data_len()
                            );

                            match self.file_server.write(
                                &opaque_handle,
                                current_write_offset,
                                data_segment.as_ref(),
                            ) {
                                Ok(_) => {
                                    if write_tracker.get_remain_data_len() > 0 {
                                        self.partial_write_request_tracker =
                                            Some(write_tracker);
                                    } else {
                                        output_wrapper
                                            .send_status(
                                                write_tracker.get_req_id(),
                                                StatusCode::SSH_FX_OK,
                                                "",
                                            )
                                            .await?;
                                        info!("Finished multi part Write Request");
                                        self.state = SftpHandleState::Idle;
                                    }
                                }
                                Err(e) => {
                                    error!("SFTP write thrown: {:?}", e);
                                    output_wrapper
                                        .send_status(
                                            write_tracker.get_req_id(),
                                            StatusCode::SSH_FX_FAILURE,
                                            "error writing",
                                        )
                                        .await?;
                                    self.state = SftpHandleState::Idle;
                                }
                            };
                            buffer_in_lower_index_bracket =
                                in_len - source.remaining();
                        }
                    }
                }

                SftpHandleState::Initializing => {
                    let (source, sftp_packet) = create_sftp_source_and_packet(
                        buffer_in,
                        buffer_in_lower_index_bracket,
                    );
                    match sftp_packet {
                        Ok(request) => {
                            match request {
                                SftpPacket::Init(_) => {
                                    let version =
                                        SftpPacket::Version(InitVersionLowest {
                                            version: SFTP_VERSION,
                                        });

                                    output_wrapper.send_packet(version).await?;
                                    self.state = SftpHandleState::Idle;
                                }
                                _ => {
                                    error!(
                                        "Request received before init: {:?}",
                                        request
                                    );
                                    return Err(SftpError::NotInitialized);
                                }
                            };
                        }
                        Err(_) => {
                            error!(
                                "Malformed SFTP Packet before Init: {:?}",
                                sftp_packet
                            );
                            return Err(SftpError::MalformedPacket);
                        }
                    }
                    buffer_in_lower_index_bracket = in_len - source.remaining();
                }
                SftpHandleState::Idle => {
                    let (mut source, sftp_packet) = create_sftp_source_and_packet(
                        buffer_in,
                        buffer_in_lower_index_bracket,
                    );
                    match sftp_packet {
                        Ok(request) => {
                            Self::handle_general_request(
                                &mut self.file_server,
                                output_wrapper,
                                request,
                            )
                            .await?;
                        }
                        Err(e) => match e {
                            WireError::RanOut => {
                                warn!(
                                    "RanOut for the SFTP Packet in the source buffer: {:?}",
                                    e
                                );

                                match Self::handle_ran_out(
                                    &mut self.file_server,
                                    output_wrapper,
                                    &mut source,
                                )
                                .await
                                {
                                    Ok(holder) => {
                                        self.partial_write_request_tracker =
                                            Some(holder);
                                        self.state =
                                                        SftpHandleState::Fragmented(FragmentedRequestState::ProcessingLongRequest)
                                    }
                                    Err(e) => {
                                        error!("Error handle_ran_out");
                                        match e {
                                            SftpError::WireError(
                                                WireError::RanOut,
                                            ) => {
                                                let read = self.incomplete_request_holder
                                                            .try_hold(
                                                            &buffer_in
                                                                [buffer_in_lower_index_bracket..],
                                                        )?;
                                                buffer_in_lower_index_bracket +=
                                                    read;
                                                self.state = SftpHandleState::Fragmented(FragmentedRequestState::ProcessingClippedRequest);
                                                continue;
                                            }
                                            _ => {
                                                return Err(SunsetError::Bug.into());
                                            }
                                        }
                                    }
                                };
                            }
                            _ => {
                                error!("Error decoding SFTP Packet: {:?}", e);
                                output_wrapper
                                    .send_status(
                                        ReqId(u32::MAX),
                                        StatusCode::SSH_FX_OP_UNSUPPORTED,
                                        "Error decoding SFTP Packet",
                                    )
                                    .await?;
                            }
                        },
                    };
                    buffer_in_lower_index_bracket = in_len - source.remaining();
                }
            }
        }

        Ok(())
    }

    /// WIP: A loop that will process all the request from stdio until
    /// an EOF is received
    pub async fn process_loop<'c>(
        &mut self,
        stdio: ChanInOut<'c>,
        buffer_in: &mut [u8],
        buffer_out: &'a mut [u8],
    ) -> SftpResult<()> {
        let (mut chan_in, chan_out) = stdio.split();

        let mut chan_out_wrapper =
            SftpOutputChannelWrapper::new(buffer_out, chan_out);
        loop {
            let lr = chan_in.read(buffer_in).await?;
            trace!("SFTP <---- received: {:?}", &buffer_in[0..lr]);
            if lr == 0 {
                debug!("client disconnected");
                return Err(SftpError::ClientDisconnected);
            }

            self.process(&buffer_in[0..lr], &mut chan_out_wrapper).await?;
        }
    }

    async fn handle_general_request<'g>(
        file_server: &mut S,
        output_wrapper: &mut SftpOutputChannelWrapper<'a, 'g>,
        request: SftpPacket<'_>,
    ) -> Result<(), SftpError>
    where
        T: OpaqueFileHandle,
    {
        debug!("Handling general request: {:?}", request);
        match request {
            SftpPacket::Init(_) => {
                error!("The Init packet is not a request but an initialization");
                return Err(SftpError::AlreadyInitialized);
            }
            SftpPacket::PathInfo(req_id, path_info) => {
                let a_name = file_server.realpath(path_info.path.as_str()?)?;

                let response = SftpPacket::Name(req_id, a_name);
                debug!(
                    "Request Id {:?}. Encoding response: {:?}",
                    &req_id, &response
                );

                output_wrapper.send_packet(response).await?;
            }
            SftpPacket::Open(req_id, open) => {
                match file_server.open(open.filename.as_str()?, &open.attrs) {
                    Ok(opaque_file_handle) => {
                        let response = SftpPacket::Handle(
                            req_id,
                            proto::Handle {
                                handle: opaque_file_handle.into_file_handle(),
                            },
                        );
                        output_wrapper.send_packet(response).await?;
                    }
                    Err(status_code) => {
                        error!("Open failed: {:?}", status_code);
                        output_wrapper
                            .send_status(req_id, StatusCode::SSH_FX_FAILURE, "")
                            .await?;
                    }
                };
            }
            // TODO The visitor behavioral pattern could be use in write to speed-up
            // the writing process
            SftpPacket::Write(req_id, write) => {
                match file_server.write(
                    &T::try_from(&write.handle)?,
                    write.offset,
                    write.data.as_ref(),
                ) {
                    Ok(_) => {
                        output_wrapper
                            .send_status(req_id, StatusCode::SSH_FX_OK, "")
                            .await?;
                    }
                    Err(e) => {
                        error!("SFTP write thrown: {:?}", e);
                        output_wrapper
                            .send_status(
                                req_id,
                                StatusCode::SSH_FX_FAILURE,
                                "error writing",
                            )
                            .await?;
                    }
                };
            }
            SftpPacket::Close(req_id, close) => {
                match file_server.close(&T::try_from(&close.handle)?) {
                    Ok(_) => {
                        output_wrapper
                            .send_status(req_id, StatusCode::SSH_FX_OK, "")
                            .await?;
                    }
                    Err(e) => {
                        error!("SFTP Close thrown: {:?}", e);
                        output_wrapper
                            .send_status(
                                req_id,
                                StatusCode::SSH_FX_FAILURE,
                                "Could not Close the handle",
                            )
                            .await?;
                    }
                }
            }
            SftpPacket::OpenDir(req_id, open_dir) => {
                match file_server.opendir(open_dir.dirname.as_str()?) {
                    Ok(opaque_file_handle) => {
                        let response = SftpPacket::Handle(
                            req_id,
                            proto::Handle {
                                handle: opaque_file_handle.into_file_handle(),
                            },
                        );
                        output_wrapper.send_packet(response).await?;
                    }
                    Err(status_code) => {
                        error!("Open failed: {:?}", status_code);
                        output_wrapper
                            .send_status(req_id, StatusCode::SSH_FX_FAILURE, "")
                            .await?;
                    }
                };
            }
            SftpPacket::ReadDir(req_id, read_dir) => {
                // TODO Implement the mechanism you are going to use to
                // handle the list of elements

                let mut dir_reply = DirReply::new(req_id, output_wrapper);

                match file_server
                    .readdir(&T::try_from(&read_dir.handle)?, &mut dir_reply)
                {
                    Ok(_) => {
                        todo!("Dance starts here");
                    }
                    Err(status_code) => {
                        error!("Open failed: {:?}", status_code);
                        // output_wrapper
                        //     .push_status(
                        //         req_id,
                        //         StatusCode::SSH_FX_OP_UNSUPPORTED,
                        //         "Error Reading Directory",
                        //     )
                        //     .await?;
                    }
                };
                error!("Unsupported Read Dir : {:?}", read_dir);
                // return Err(SftpError::NotSupported);
                // push_unsupported(ReqId(0), sink)?;
            }
            _ => {
                error!("Unsupported request type: {:?}", request);
                return Err(SftpError::NotSupported);
                // push_unsupported(ReqId(0), sink)?;
            }
        }
        Ok(())
    }

    // TODO Handle more long requests
    /// Some long request will not fit in the channel buffers. Such requests
    /// will require to be handled differently. Gathering the data in and
    /// processing it as we receive it in the channel in buffer.
    ///
    /// In the current approach a tracker is required to store the state of
    /// the processing of such long requests.
    ///
    /// With an implementation that where able to hold the channel_in there might
    /// be no need to keep this tracker.
    ///
    /// **WARNING:** Only `SSH_FXP_WRITE` has been implemented!
    ///
    async fn handle_ran_out<'g>(
        file_server: &mut S,
        output_wrapper: &mut SftpOutputChannelWrapper<'a, 'g>,
        source: &mut SftpSource<'_>,
    ) -> SftpResult<PartialWriteRequestTracker<T>> {
        let packet_type = source.peak_packet_type()?;
        match packet_type {
            SftpNum::SSH_FXP_WRITE => {
                debug!(
                    "about to decode packet partial write content. Source remaining = {:?}",
                    source.remaining()
                );
                let (
                    obscured_file_handle,
                    req_id,
                    offset,
                    data_in_buffer,
                    write_tracker,
                ) = source
                    .dec_packet_partial_write_content_and_get_tracker::<T>()?;

                trace!(
                    "obscured_file_handle = {:?}, req_id = {:?}, \
                    offset = {:?}, data_in_buffer = {:?}, \
                    write_tracker = {:?}",
                    obscured_file_handle,
                    req_id,
                    offset,
                    data_in_buffer,
                    write_tracker,
                );

                match file_server.write(
                    &obscured_file_handle,
                    offset,
                    data_in_buffer.as_ref(),
                ) {
                    Ok(_) => {
                        debug!(
                            "Storing a write tracker for a fragmented write request"
                        );
                        return Ok(write_tracker);
                    }
                    Err(e) => {
                        error!("SFTP write thrown: {:?}", e);
                        output_wrapper
                            .send_status(
                                req_id,
                                StatusCode::SSH_FX_FAILURE,
                                "error writing ",
                            )
                            .await?;
                        return Err(SftpError::FileServerError(e));
                    }
                };
            }
            _ => {
                error!(
                    "RanOut of Packet type could not be handled {:?}",
                    packet_type
                );
                return Err(SftpError::NotSupported);
            }
        };
        // Ok(())
    }
}
/// Function to create an SFTP source and decode an SFTP packet from it
/// to avoid code duplication
fn create_sftp_source_and_packet(
    buffer_in: &[u8],
    buffer_in_lower_index_bracket: usize,
) -> (SftpSource<'_>, Result<SftpPacket<'_>, WireError>) {
    let mut source = SftpSource::new(&buffer_in[buffer_in_lower_index_bracket..]);

    let sftp_packet = SftpPacket::decode_request(&mut source);
    (source, sftp_packet)
}
