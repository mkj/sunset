use crate::handles::OpaqueFileHandle;
use crate::proto::ReqId;
use sunset::sshwire::WireResult;

// TODO Generalize this to allow other request types
/// Used to keep record of a long SFTP Write request that does not fit in
/// receiving buffer and requires processing in batches
#[derive(Debug)]
pub struct PartialWriteRequestTracker<T: OpaqueFileHandle> {
    req_id: ReqId,
    opaque_handle: T,
    remain_data_len: u32,
    remain_data_offset: u64,
}

impl<T: OpaqueFileHandle> PartialWriteRequestTracker<T> {
    /// Creates a new [`PartialWriteRequestTracker`]
    pub fn new(
        req_id: ReqId,
        opaque_handle: T,
        remain_data_len: u32,
        remain_data_offset: u64,
    ) -> WireResult<Self> {
        Ok(PartialWriteRequestTracker {
            req_id,
            opaque_handle: opaque_handle,
            remain_data_len,
            remain_data_offset,
        })
    }
    /// Returns the opaque file handle associated with the request
    /// tracked
    pub fn get_opaque_file_handle(&self) -> T {
        self.opaque_handle.clone()
    }

    pub fn get_remain_data_len(&self) -> u32 {
        self.remain_data_len
    }

    pub fn get_remain_data_offset(&self) -> u64 {
        self.remain_data_offset
    }

    // pub fn add_to_remain_data_offset(&mut self, add_offset: u64) {
    //     self.remain_data_offset += add_offset;
    // }

    pub(crate) fn update_remaining_after_partial_write(
        &mut self,
        data_segment_len: u32,
    ) -> () {
        self.remain_data_offset += data_segment_len as u64;
        self.remain_data_len -= data_segment_len;
    }

    pub(crate) fn get_req_id(&self) -> ReqId {
        self.req_id.clone() // TODO reference?
    }
}
