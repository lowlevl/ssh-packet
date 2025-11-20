//! Messages involved in the SSH's **transport** (`SSH-TRANS`) part of the protocol,
//! as defined in the [RFC 4253](https://datatracker.ietf.org/doc/html/rfc4253)
//! and [RFC 5656](https://datatracker.ietf.org/doc/html/rfc5656).

use binrw::binrw;

use super::{Packet, arch};

impl Packet for Disconnect<'_> {}
impl Packet for Ignore<'_> {}
impl Packet for Unimplemented {}
impl Packet for Debug<'_> {}
impl Packet for ServiceRequest<'_> {}
impl Packet for ServiceAccept<'_> {}
impl Packet for KexInit<'_> {}
impl Packet for NewKeys {}
impl Packet for KexdhInit<'_> {}
impl Packet for KexdhReply<'_> {}
impl Packet for KexEcdhInit<'_> {}
impl Packet for KexEcdhReply<'_> {}

/// The `SSH_MSG_DISCONNECT` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-11.1>.
#[binrw]
#[derive(Debug, Clone)]
#[brw(big, magic = 1_u8)]
pub struct Disconnect<'b> {
    /// Reason for disconnection.
    pub reason: DisconnectReason,

    /// Description of the reason for disconnection.
    pub description: arch::Utf8<'b>,

    /// Language tag.
    pub language: arch::Ascii<'b>,
}

/// The `reason` for disconnect in the `SSH_MSG_DISCONNECT` message.
#[binrw]
#[derive(Debug, Clone)]
#[brw(big)]
pub enum DisconnectReason {
    /// `SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT`.
    #[brw(magic = 1_u32)]
    HostNotAllowedToConnect,

    /// `SSH_DISCONNECT_PROTOCOL_ERROR`.
    #[brw(magic = 2_u32)]
    ProtocolError,

    /// `SSH_DISCONNECT_KEY_EXCHANGE_FAILED`.
    #[brw(magic = 3_u32)]
    KeyExchangeFailed,

    /// `SSH_DISCONNECT_RESERVED`.
    #[brw(magic = 4_u32)]
    Reserved,

    /// `SSH_DISCONNECT_MAC_ERROR`.
    #[brw(magic = 5_u32)]
    MacError,

    /// `SSH_DISCONNECT_COMPRESSION_ERROR`.
    #[brw(magic = 6_u32)]
    CompressionError,

    /// `SSH_DISCONNECT_SERVICE_NOT_AVAILABLE`.
    #[brw(magic = 7_u32)]
    ServiceNotAvailable,

    /// `SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED`.
    #[brw(magic = 8_u32)]
    ProtocolVersionNotSupported,

    /// `SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE`.
    #[brw(magic = 9_u32)]
    HostKeyNotVerifiable,

    /// `SSH_DISCONNECT_CONNECTION_LOST`.
    #[brw(magic = 10_u32)]
    ConnectionLost,

    /// `SSH_DISCONNECT_BY_APPLICATION`.
    #[brw(magic = 11_u32)]
    ByApplication,

    /// `SSH_DISCONNECT_TOO_MANY_CONNECTIONS`.
    #[brw(magic = 12_u32)]
    TooManyConnections,

    /// `SSH_DISCONNECT_AUTH_CANCELLED_BY_USER`.
    #[brw(magic = 13_u32)]
    AuthCancelledByUser,

    /// `SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE`.
    #[brw(magic = 14_u32)]
    NoMoreAuthMethodsAvailable,

    /// `SSH_DISCONNECT_ILLEGAL_USER_NAME`.
    #[brw(magic = 15_u32)]
    IllegalUserName,

    /// Any other disconnect reason, may be non-standard.
    ///
    /// The 'reason' values in the range of `0xFE000000`
    /// through `0xFFFFFFFF` are reserved for PRIVATE USE.
    Other(u32),
}

/// The `SSH_MSG_IGNORE` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-11.2>.
#[binrw]
#[derive(Debug, Default, Clone)]
#[brw(big, magic = 2_u8)]
pub struct Ignore<'b> {
    /// A random blob of data to ignore.
    pub data: arch::Bytes<'b>,
}

/// The `SSH_MSG_UNIMPLEMENTED` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-11.4>.
#[binrw]
#[derive(Debug, Clone)]
#[brw(big, magic = 3_u8)]
pub struct Unimplemented {
    /// Packet sequence number of rejected message.
    pub seq: u32,
}

/// The `SSH_MSG_DEBUG` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-11.3>.
#[binrw]
#[derive(Debug, Default, Clone)]
#[brw(big, magic = 4_u8)]
pub struct Debug<'b> {
    /// Whether the debug data should be forcefully displayed.
    pub always_display: arch::Bool,

    /// The debug message.
    pub message: arch::Utf8<'b>,

    /// Language tag.
    pub language: arch::Ascii<'b>,
}

/// The `SSH_MSG_SERVICE_REQUEST` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-10>.
#[binrw]
#[derive(Debug, Clone)]
#[brw(big, magic = 5_u8)]
pub struct ServiceRequest<'b> {
    /// The service name to request.
    pub service_name: arch::Ascii<'b>,
}

/// The `SSH_MSG_SERVICE_ACCEPT` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-10>.
#[binrw]
#[derive(Debug, Clone)]
#[brw(big, magic = 6_u8)]
pub struct ServiceAccept<'b> {
    /// Service name accepted to be requested.
    pub service_name: arch::Ascii<'b>,
}

/// The `SSH_MSG_KEXINIT` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-7.1>.
#[binrw]
#[derive(Debug, Clone)]
#[brw(big, magic = 20_u8)]
pub struct KexInit<'b> {
    /// The kex-init cookie.
    pub cookie: [u8; 16],

    /// Kex algorithms.
    pub kex_algorithms: arch::NameList<'b>,

    /// Server host-key algorithms.
    pub server_host_key_algorithms: arch::NameList<'b>,

    /// Client -> server encryption algorithms.
    pub encryption_algorithms_client_to_server: arch::NameList<'b>,

    /// Server -> client encryption algorithms.
    pub encryption_algorithms_server_to_client: arch::NameList<'b>,

    /// Client -> server MAC algorithms.
    pub mac_algorithms_client_to_server: arch::NameList<'b>,

    /// Server -> client MAC algorithms.
    pub mac_algorithms_server_to_client: arch::NameList<'b>,

    /// Client -> server compression algorithms.
    pub compression_algorithms_client_to_server: arch::NameList<'b>,

    /// Server -> client compression algorithms.
    pub compression_algorithms_server_to_client: arch::NameList<'b>,

    /// Client -> server languages.
    pub languages_client_to_server: arch::NameList<'b>,

    /// Server -> client languages.
    pub languages_server_to_client: arch::NameList<'b>,

    /// Whether the first kex packet follows.
    pub first_kex_packet_follows: arch::Bool,

    #[bw(calc = 0)]
    _reserved: u32,
}

/// The `SSH_MSG_NEWKEYS` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-7.3>.
#[binrw]
#[derive(Debug, Default, Clone)]
#[brw(big, magic = 21_u8)]
pub struct NewKeys;

/// The `SSH_MSG_KEXDH_INIT` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-8>.
#[binrw]
#[derive(Debug, Clone)]
#[brw(big, magic = 30_u8)]
pub struct KexdhInit<'b> {
    /// Exchange value sent by the client.
    pub e: arch::MpInt<'b>,
}

/// The `SSH_MSG_KEXDH_REPLY` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-8>.
#[binrw]
#[derive(Debug, Clone)]
#[brw(big, magic = 31_u8)]
pub struct KexdhReply<'b> {
    /// Server's public host key.
    pub k_s: arch::Bytes<'b>,

    /// Exchange value sent by the server.
    pub f: arch::MpInt<'b>,

    /// Signature of the exchange hash.
    pub signature: arch::Bytes<'b>,
}

/// The `SSH_MSG_KEX_ECDH_INIT` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc5656#section-4>.
#[binrw]
#[derive(Debug, Clone)]
#[brw(big, magic = 30_u8)]
pub struct KexEcdhInit<'b> {
    /// Client's ephemeral public key octet string.
    pub q_c: arch::Bytes<'b>,
}

/// The `SSH_MSG_KEX_ECDH_REPLY` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc5656#section-4>.
#[binrw]
#[derive(Debug, Clone)]
#[brw(big, magic = 31_u8)]
pub struct KexEcdhReply<'b> {
    /// Server's public host key.
    pub k_s: arch::Bytes<'b>,

    /// Server's ephemeral public key octet string.
    pub q_s: arch::Bytes<'b>,

    /// Signature of the exchange hash.
    pub signature: arch::Bytes<'b>,
}
