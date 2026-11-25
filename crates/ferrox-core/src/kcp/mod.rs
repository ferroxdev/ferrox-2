mod config;
mod connection;
mod listener;
mod mask;
mod roundtrip;
mod segment;
mod window;
mod worker;

#[cfg(test)]
mod oracle;

pub use config::Config;
pub use connection::{ConnError, ConnMetadata, Connection, State};
pub use listener::{Listener, dial, dial_with, fresh_conversation};
pub use mask::{Encoder, HeaderKind, Mask, Spec, SpecError};
pub use segment::{
    AckSegment, CmdOnlySegment, Command, DATA_SEGMENT_OVERHEAD, DataSegment, Segment, SegmentOption,
};

pub use roundtrip::RoundTripInfo;
pub use segment::read_segment;
pub use window::{AckList, ReceivingWindow, SendingWindow};
pub use worker::{ReceivingWorker, SendingWorker};
