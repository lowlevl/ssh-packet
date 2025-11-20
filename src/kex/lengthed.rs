use std::{io, ops::Deref};

use binrw::{
    BinRead, BinWrite,
    meta::{ReadEndian, WriteEndian},
};

use crate::MAX_SIZE;

/// An helper to prefix a serializable value with it's `size`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Lengthed<T>(pub T);

impl<T> Deref for Lengthed<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> From<T> for Lengthed<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> BinRead for Lengthed<T>
where
    T: BinRead,
{
    type Args<'a> = T::Args<'a>;

    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        endian: binrw::Endian,
        args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let size = u32::read_be(reader)?;
        let len = (size as usize).min(MAX_SIZE);

        let mut buf = Vec::with_capacity(len);
        reader.read_exact(&mut buf[..len])?;

        T::read_options(&mut io::Cursor::new(&buf), endian, args).map(Self)
    }
}

impl<T> ReadEndian for Lengthed<T>
where
    T: ReadEndian,
{
    const ENDIAN: binrw::meta::EndianKind = T::ENDIAN;
}

impl<T> BinWrite for Lengthed<T>
where
    T: BinWrite,
{
    type Args<'a> = T::Args<'a>;

    fn write_options<W: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut W,
        endian: binrw::Endian,
        args: Self::Args<'_>,
    ) -> binrw::BinResult<()> {
        let mut buf = Vec::with_capacity(MAX_SIZE);
        self.0
            .write_options(&mut io::Cursor::new(&mut buf), endian, args)?;

        let len = buf.len();
        let size: u32 = len.min(MAX_SIZE) as u32;

        size.write_be(writer)?;
        Ok(writer.write_all(&buf)?)
    }
}

impl<T> WriteEndian for Lengthed<T>
where
    T: WriteEndian,
{
    const ENDIAN: binrw::meta::EndianKind = T::ENDIAN;
}
