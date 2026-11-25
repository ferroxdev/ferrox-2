pub mod cfb8;
pub mod derivation;
pub mod packet_stream;
pub mod padding;
pub mod padding_preset;
pub mod profile;
pub mod protocol;
pub mod session;

pub use cfb8::Cfb8;
pub use derivation::{derive_rsa_key, private_key_der, public_key_der};
pub use packet_stream::PacketStream;
pub use padding::{DelayRange, Direction, Turn, Variant, run, validate_schedule};
pub use padding_preset::{new_client_schedule, new_server_schedule};
pub use profile::{Profile, find_profile, profiles_from_config, read_login_success};
pub use protocol::{
    Long, Packet, UnsignedShort, decode_packet_body, encode_packet, read_boolean, read_byte,
    read_bytes, read_frame, read_long, read_packet, read_packet_with_length, read_remaining,
    read_string, read_unsigned_short, read_uuid, read_varint, read_varint_with_length, varint_size,
    write_boolean, write_bytes, write_disconnect_packet, write_long, write_packet,
    write_packet_with_length, write_remaining, write_string, write_unsigned_short, write_uuid,
    write_varint,
};
pub use session::{Config, Session};

thread_local! {
    static READY: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Whether this thread's XMC write is a readiness offer that must not wait on a held lock.
pub fn ready() -> bool {
    READY.with(|ready| ready.get() > 0)
}

/// Marks the current thread's XMC write as a readiness offer for as long as the guard lives.
#[derive(Debug)]
pub struct ReadyWrite(());

impl ReadyWrite {
    pub fn enter() -> Self {
        READY.with(|ready| ready.set(ready.get() + 1));
        Self(())
    }
}

impl Drop for ReadyWrite {
    fn drop(&mut self) {
        READY.with(|ready| ready.set(ready.get().saturating_sub(1)));
    }
}
