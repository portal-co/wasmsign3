use core::slice;

use embedded_io::{ErrorKind, ErrorType, Read, ReadExactError, Write};
use sha3::Digest;

pub fn get<E>(
    reader: &mut impl Read<Error = E>,
    mut decr_read: Option<&mut u64>,
) -> Result<u64, ReadExactError<E>> {
    let mut v: u64 = 0;
    loop {
        for i in 0.. {
            let mut byte = [0u8; 1];
            reader.read_exact(&mut byte)?;
            if let Some(d) = decr_read.as_deref_mut() {
                *d -= 1
            }
            v |= ((byte[0] & 0x7f) as u64) << (i * 7);
            if (byte[0] & 0x80) == 0 {
                return Ok(v);
            }
        }
    }
    // Err(WSError::ParseError)
}

pub fn put<E>(writer: &mut impl Write<Error = E>, mut v: u64) -> Result<(), E> {
    let mut byte = [0u8; 1];
    loop {
        byte[0] = (v & 0x7f) as u8;
        if v > 0x7f {
            byte[0] |= 0x80;
        }
        writer.write_all(&byte)?;
        v >>= 7;
        if v == 0 {
            return Ok(());
        }
    }
}
pub fn put_pad<E>(writer: &mut impl Write<Error = E>, mut v: u64) -> Result<(), E> {
    let mut byte = [0u8; 1];
    for _ in 0..10 {
        byte[0] = (v & 0x7f) as u8;
        if v > 0x7f {
            byte[0] |= 0x80;
        }
        writer.write_all(&byte)?;
        v >>= 7;
    }
    Ok(())
}
pub fn read_custom_section<E, R: Read<Error = E>>(
    reader: &mut R,
    name_hash: Option<[u8; 32]>,
) -> Result<CustomSection<'_, R>, ReadExactError<E>> {
    loop {
        let mut b = 0u8;
        reader.read_exact(slice::from_mut(&mut b))?;
        let mut g = get(reader, None)?;
        match b {
            0 => match name_hash.as_ref() {
                None => return Ok(CustomSection { len: g, reader }),
                Some(n) => {
                    let a = get(reader, Some(&mut g))?;
                    let mut s = sha3::Sha3_256::default();
                    for _ in 0..a {
                        reader.read_exact(slice::from_mut(&mut b))?;
                        s.update(&[b]);
                    }
                    let s: [u8; 32] = s.finalize().into();
                    if s == *n {
                        return Ok(CustomSection { len: g, reader });
                    } else {
                        while g != 0 {
                            reader.read_exact(slice::from_mut(&mut b))?;
                        }
                    }
                }
            },
            _ => {
                while g != 0 {
                    reader.read_exact(slice::from_mut(&mut b))?;
                }
            }
        }
    }
}
// #[non_exhaustive]
pub struct CustomSection<'a, R> {
    pub len: u64,
    pub reader: &'a mut R,
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
#[macro_export]
macro_rules! read_custom_section_with_name {
    ($a:expr, $b:expr) => {
        $crate::module::read_custom_section(
            $a,
            $crate::__::core::option::Option::Some($crate::__::sha3_literal!($b)),
        )
    };
}
