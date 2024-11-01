use crate::Error;

const VERSION: &str = "2.0";

/// The SSH identification string as defined in the SSH protocol.
///
/// The format must match the following pattern:
/// `SSH-<protoversion>-<softwareversion>[ <comments>]`.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-4.2>.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Id {
    /// The SSH's protocol version, should be `2.0` in our case.
    pub protoversion: String,

    /// A string identifying the software curently used, in example `billsSSH_3.6.3q3`.
    pub softwareversion: String,

    /// Optional comments with additionnal informations about the software.
    pub comments: Option<String>,
}

impl Id {
    /// Convenience method to create an `SSH-2.0` identifier string.
    pub fn v2(softwareversion: impl Into<String>, comments: Option<impl Into<String>>) -> Self {
        Self {
            protoversion: VERSION.into(),
            softwareversion: softwareversion.into(),
            comments: comments.map(Into::into),
        }
    }

    #[cfg(feature = "futures")]
    #[cfg_attr(docsrs, doc(cfg(feature = "futures")))]
    /// Read an [`Id`], discarding any _extra lines_ sent by the server
    /// from the provided asynchronous `reader`.
    pub async fn from_reader<R>(reader: &mut R) -> Result<Self, Error>
    where
        R: futures::io::AsyncBufRead + Unpin,
    {
        use futures::TryStreamExt;

        let text = futures::io::AsyncBufReadExt::lines(reader)
            // Skip extra lines the server can send before identifying
            .try_skip_while(|line| futures::future::ok(!line.starts_with("SSH")))
            .try_next()
            .await?
            .ok_or(Error::UnexpectedEof)?;

        text.parse()
    }

    #[cfg(feature = "futures")]
    #[cfg_attr(docsrs, doc(cfg(feature = "futures")))]
    /// Write the [`Id`] to the provided asynchronous `writer`.
    pub async fn to_writer<W>(&self, writer: &mut W) -> Result<(), Error>
    where
        W: futures::io::AsyncWrite + Unpin,
    {
        use futures::io::AsyncWriteExt;

        writer.write_all(self.to_string().as_bytes()).await?;
        writer.write_all(b"\r\n").await?;

        Ok(())
    }
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SSH-{}-{}", self.protoversion, self.softwareversion)?;

        if let Some(comments) = &self.comments {
            write!(f, " {comments}")?;
        }

        Ok(())
    }
}

impl std::str::FromStr for Id {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (id, comments) = s
            .split_once(' ')
            .map_or_else(|| (s, None), |(id, comments)| (id, Some(comments)));

        match id.splitn(3, '-').collect::<Vec<_>>()[..] {
            ["SSH", protoversion, softwareversion]
                if !protoversion.is_empty() && !softwareversion.is_empty() =>
            {
                Ok(Self {
                    protoversion: protoversion.to_string(),
                    softwareversion: softwareversion.to_string(),
                    comments: comments.map(str::to_string),
                })
            }
            _ => Err(Error::BadIdentifer(s.into())),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::unimplemented)]
    use rstest::rstest;
    use std::str::FromStr;

    use super::*;

    impl PartialEq for Error {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (Self::Io(l0), Self::Io(r0)) => l0.kind() == r0.kind(),
                _ => core::mem::discriminant(self) == core::mem::discriminant(other),
            }
        }
    }

    #[rstest]
    #[case("SSH-2.0-billsSSH_3.6.3q3")]
    #[case("SSH-1.99-billsSSH_3.6.3q3")]
    #[case("SSH-2.0-billsSSH_3.6.3q3 with-comment")]
    #[case("SSH-2.0-billsSSH_3.6.3q3 utf∞-comment")]
    #[case("SSH-2.0-billsSSH_3.6.3q3 ")] // empty comment
    fn it_parses_valid(#[case] text: &str) {
        Id::from_str(text).expect(text);
    }

    #[rstest]
    #[case("")]
    #[case("FOO-2.0-billsSSH_3.6.3q3")]
    #[case("-2.0-billsSSH_3.6.3q3")]
    #[case("SSH--billsSSH_3.6.3q3")]
    #[case("SSH-2.0-")]
    fn it_rejects_invalid(#[case] text: &str) {
        Id::from_str(text).expect_err(text);
    }

    #[rstest]
    #[case(Id::v2("billsSSH_3.6.3q3", None::<String>))]
    #[case(Id::v2("billsSSH_utf∞", None::<String>))]
    #[case(Id::v2("billsSSH_3.6.3q3", Some("with-comment")))]
    #[case(Id::v2("billsSSH_3.6.3q3", Some("utf∞-comment")))]
    #[case(Id::v2("billsSSH_3.6.3q3", Some("")))] // empty comment
    fn it_reparses_consistently(#[case] id: Id) {
        assert_eq!(id, id.to_string().parse().unwrap());
    }
}
