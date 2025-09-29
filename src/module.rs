use core::slice;

use embedded_io::{ErrorKind, ErrorType, Read, ReadExactError, Write};
use sha3::Digest;

pub fn get<E>(
    reader: &mut impl Read<Error = E>,
    mut decr_read: Option<&mut u64>,
) -> Result<u64, ReadExactError<E>> {
    let mut value: u64 = 0;
    loop {
        for i in 0.. {
            let mut byte = [0u8; 1];
            reader.read_exact(&mut byte)?;
            if let Some(d) = decr_read.as_deref_mut() {
                *d -= 1
            }
            value |= ((byte[0] & 0x7f) as u64) << (i * 7);
            if (byte[0] & 0x80) == 0 {
                return Ok(value);
            }
        }
    }
    // Err(WSError::ParseError)
}

pub fn put<E>(writer: &mut impl Write<Error = E>, mut value: u64) -> Result<(), E> {
    let mut byte = [0u8; 1];
    loop {
        byte[0] = (value & 0x7f) as u8;
        if value > 0x7f {
            byte[0] |= 0x80;
        }
        writer.write_all(&byte)?;
        value >>= 7;
        if value == 0 {
            return Ok(());
        }
    }
}
pub fn put_pad<E>(writer: &mut impl Write<Error = E>, mut value: u64) -> Result<(), E> {
    let mut byte = [0u8; 1];
    for _ in 0..10 {
        byte[0] = (value & 0x7f) as u8;
        if value > 0x7f {
            byte[0] |= 0x80;
        }
        writer.write_all(&byte)?;
        value >>= 7;
    }
    Ok(())
}
pub fn read_custom_section<E, R: Read<Error = E>>(
    reader: &mut R,
    name_hash: Option<[u8; 32]>,
) -> Result<CustomSection<'_, R>, ReadExactError<E>> {
    loop {
        let mut ty = 0u8;
        reader.read_exact(slice::from_mut(&mut ty))?;
        let mut len = get(reader, None)?;
        match ty {
            0 => match name_hash.as_ref() {
                None => return Ok(CustomSection { len, reader }),
                Some(name_hash) => {
                    let name_len = get(reader, Some(&mut len))?;
                    let mut hash = sha3::Sha3_256::default();
                    for _ in 0..name_len {
                        reader.read_exact(slice::from_mut(&mut ty))?;
                        hash.update(&[ty]);
                    }
                    let hash: [u8; 32] = hash.finalize().into();
                    if hash == *name_hash {
                        return Ok(CustomSection { len, reader });
                    } else {
                        while len != 0 {
                            reader.read_exact(slice::from_mut(&mut ty))?;
                        }
                    }
                }
            },
            _ => {
                while len != 0 {
                    reader.read_exact(slice::from_mut(&mut ty))?;
                }
            }
        }
    }
}
// #[non_exhaustive]
pub struct CustomSection<'a, R> {
    len: u64,
    reader: &'a mut R,
}
impl<'a, R: Read> ErrorType for CustomSection<'a, R> {
    type Error = R::Error;
}
impl<'a, R: Read> Read for CustomSection<'a, R> {
    fn read(&mut self, mut buf: &mut [u8]) -> Result<usize, Self::Error> {
        if buf.len() as u64 > self.len {
            buf = &mut buf[..(self.len as usize)];
        }
        let a = self.reader.read(buf)?;
        self.len -= (a as u64);
        return Ok(a);
    }
}
impl<'a,R> CustomSection<'a,R>{
    pub fn len(&self) -> u64{
        return self.len;
    }
    pub fn take(self) -> Result<&'a mut R,Self>{
        match self.len{
            0 => Ok(self.reader),
            _ => Err(self)
        }
    }
}
#[macro_export]
macro_rules! read_custom_section_with_name {
    ($a:expr, $b:expr) => {
        $crate::module::read_custom_section(
            $a,
            $crate::__::core::option::Option::Some($crate::__::sha3_literal!($b)),
        )
    };
}
