//! Messages involved in the SSH's **authentication** (`SSH-USERAUTH`) part of the protocol,
//! as defined in the [RFC 4252](https://datatracker.ietf.org/doc/html/rfc4252) and [RFC 4256](https://datatracker.ietf.org/doc/html/rfc4256).

use binrw::binrw;

use super::{Packet, arch};

impl Packet for Request<'_> {}
impl Packet for Failure<'_> {}
impl Packet for Success {}
impl Packet for Banner<'_> {}
impl Packet for PkOk<'_> {}
impl Packet for PasswdChangereq<'_> {}
impl Packet for InfoRequest<'_> {}
impl Packet for InfoResponse {}

/// The `SSH_MSG_USERAUTH_REQUEST` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4252#section-5>.
#[binrw]
#[derive(Debug, Clone)]
#[brw(big, magic = 50_u8)]
pub struct Request<'b> {
    /// Username for the auth request.
    pub username: arch::Utf8<'b>,

    /// Service name to query.
    pub service_name: arch::Ascii<'b>,

    #[bw(calc = method.as_ascii())]
    auth_method: arch::Ascii<'b>,

    /// Authentication method used.
    #[br(args(auth_method))]
    pub method: Method<'b>,
}

/// The authentication method in the `SSH_MSG_USERAUTH_REQUEST` message.
#[binrw]
#[derive(Debug, Clone)]
#[br(import(method: arch::Ascii<'_>))]
pub enum Method<'b> {
    /// Authenticate using the `none` method,
    /// as defined in [RFC4252 section 5.2](https://datatracker.ietf.org/doc/html/rfc4252#section-5.2).
    #[br(pre_assert(method == Method::NONE))]
    None,

    /// Authenticate using the `publickey` method,
    /// as defined in [RFC4252 section 7](https://datatracker.ietf.org/doc/html/rfc4252#section-7).
    #[br(pre_assert(method == Method::PUBLICKEY))]
    Publickey {
        #[bw(calc = arch::Bool::from(signature.is_some()))]
        signed: arch::Bool,

        /// Public key algorithm's name.
        algorithm: arch::Bytes<'b>,
        /// Public key blob.
        blob: arch::Bytes<'b>,

        /// The optional signature of the authentication packet,
        /// signed with the according private key.
        #[br(if(*signed))]
        signature: Option<arch::Bytes<'b>>,
    },

    /// Authenticate using the `password` method,
    /// as defined in [RFC4252 section 8](https://datatracker.ietf.org/doc/html/rfc4252#section-8).
    #[br(pre_assert(method == Method::PASSWORD))]
    Password {
        #[bw(calc = arch::Bool::from(new.is_some()))]
        change: arch::Bool,

        /// Plaintext password.
        password: arch::Utf8<'b>,

        /// In the case of a the receival of a [`PasswdChangereq`],
        /// the new password to be set in place of the old one.
        #[br(if(*change))]
        new: Option<arch::Utf8<'b>>,
    },

    /// Authenticate using the `hostbased` method,
    /// as defined in [RFC4252 section 9](https://datatracker.ietf.org/doc/html/rfc4252#section-9).
    #[br(pre_assert(method == Method::HOSTBASED))]
    Hostbased {
        /// Public key algorithm for the host key.
        algorithm: arch::Bytes<'b>,

        /// Public host key and certificates for client host.
        host_key: arch::Bytes<'b>,

        /// Client host name expressed as the FQDN.
        client_fqdn: arch::Ascii<'b>,

        /// User name on the client host.
        username: arch::Utf8<'b>,

        /// The signature of the authentication packet.
        signature: arch::Bytes<'b>,
    },

    /// Authenticate using the `keyboard-interactive` method,
    /// as defined in [RFC4256 section 3.1](https://datatracker.ietf.org/doc/html/rfc4256#section-3.1).
    #[br(pre_assert(method == Method::KEYBOARD_INTERACTIVE))]
    KeyboardInteractive {
        /// Language tag.
        language: arch::Ascii<'b>,

        /// A hint for the prefered interactive submethod.
        submethods: arch::Utf8<'b>,
    },
}

impl Method<'_> {
    /// The SSH `none` authentication method.
    pub const NONE: arch::Ascii<'static> = arch::ascii!("none");

    /// The SSH `publickey` authentication method.
    pub const PUBLICKEY: arch::Ascii<'static> = arch::ascii!("publickey");

    /// The SSH `password` authentication method.
    pub const PASSWORD: arch::Ascii<'static> = arch::ascii!("password");

    /// The SSH `hostbased` authentication method.
    pub const HOSTBASED: arch::Ascii<'static> = arch::ascii!("hostbased");

    /// The SSH `keyboard-interactive` authentication method.
    pub const KEYBOARD_INTERACTIVE: arch::Ascii<'static> = arch::ascii!("keyboard-interactive");

    /// Get the [`Method`]'s SSH identifier.
    pub fn as_ascii(&self) -> arch::Ascii<'static> {
        match self {
            Self::None { .. } => Self::NONE,
            Self::Publickey { .. } => Self::PUBLICKEY,
            Self::Password { .. } => Self::PASSWORD,
            Self::Hostbased { .. } => Self::HOSTBASED,
            Self::KeyboardInteractive { .. } => Self::KEYBOARD_INTERACTIVE,
        }
    }
}

/// The `SSH_MSG_USERAUTH_FAILURE` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4252#section-5.1>.
#[binrw]
#[derive(Debug, Default, Clone)]
#[brw(big, magic = 51_u8)]
pub struct Failure<'b> {
    /// Authentications that can continue.
    pub continue_with: arch::NameList<'b>,

    /// Partial success.
    pub partial_success: arch::Bool,
}

/// The `SSH_MSG_USERAUTH_SUCCESS` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4252#section-5.1>.
#[binrw]
#[derive(Debug, Default, Clone)]
#[brw(big, magic = 52_u8)]
pub struct Success;

/// The `SSH_MSG_USERAUTH_BANNER` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4252#section-5.4>.
#[binrw]
#[derive(Debug, Default, Clone)]
#[brw(big, magic = 53_u8)]
pub struct Banner<'b> {
    /// The auth banner message.
    pub message: arch::Utf8<'b>,

    /// Language tag.
    pub language: arch::Ascii<'b>,
}

/// The `SSH_MSG_USERAUTH_PK_OK` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4252#section-7>.
#[binrw]
#[derive(Debug, Clone)]
#[brw(big, magic = 60_u8)]
pub struct PkOk<'b> {
    /// Public key algorithm name from the request.
    pub algorithm: arch::Bytes<'b>,

    /// Public key blob from the request.
    pub blob: arch::Bytes<'b>,
}

/// The `SSH_MSG_USERAUTH_PASSWD_CHANGEREQ` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4252#section-8>.
#[binrw]
#[derive(Debug, Default, Clone)]
#[brw(big, magic = 60_u8)]
pub struct PasswdChangereq<'b> {
    /// Password change prompt.
    pub prompt: arch::Utf8<'b>,

    /// Language tag (deprecated).
    pub language: arch::Ascii<'b>,
}

/// The `SSH_MSG_USERAUTH_INFO_REQUEST` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4256#section-3.2>.
#[binrw]
#[derive(Debug, Clone)]
#[brw(big, magic = 60_u8)]
pub struct InfoRequest<'b> {
    /// Name of the challenge.
    pub name: arch::Utf8<'b>,

    /// Instructions for the challenge.
    pub instruction: arch::Utf8<'b>,

    /// Language tag (deprecated).
    pub language: arch::Ascii<'b>,

    #[bw(calc = prompts.len() as u32)]
    num_prompts: u32,

    /// The challenge's prompts.
    #[br(count = num_prompts)]
    pub prompts: Vec<InfoRequestPrompt<'static>>,
}

/// A prompt in the `SSH_MSG_USERAUTH_INFO_REQUEST` message.
#[binrw]
#[derive(Debug, Clone)]
#[brw(big)]
pub struct InfoRequestPrompt<'b> {
    /// Challenge prompt text.
    pub prompt: arch::Utf8<'b>,

    /// Whether the client should echo back typed characters.
    pub echo: arch::Bool,
}

/// The `SSH_MSG_USERAUTH_INFO_RESPONSE` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4256#section-3.4>.
#[binrw]
#[derive(Debug, Clone)]
#[brw(big, magic = 61_u8)]
pub struct InfoResponse {
    #[bw(calc = responses.len() as u32)]
    num_responses: u32,

    /// Responses to the provided challenge.
    #[br(count = num_responses)]
    pub responses: Vec<arch::Utf8<'static>>,
}
