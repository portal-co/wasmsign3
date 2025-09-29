use core::slice;

use embedded_io::{ErrorKind, ErrorType, Read, ReadExactError, Write};
use sha3::Digest;

pub fn get<E: embedded_io::Error>(
    reader: &mut (dyn Read<Error = E> + '_),
    mut decr_read: Option<&mut (dyn FnMut() + '_)>,
) -> Result<u64, ReadExactError<E>> {
    let mut value: u64 = 0;
    loop {
        for i in 0.. {
            let mut byte = [0u8; 1];
            reader.read_exact(&mut byte)?;
            if let Some(d) = decr_read.as_deref_mut() {
                d();
            }
            value |= ((byte[0] & 0x7f) as u64) << (i * 7);
            if (byte[0] & 0x80) == 0 {
                return Ok(value);
            }
        }
    }
    // Err(WSError::ParseError)
}

pub fn put<E: embedded_io::Error>(
    writer: &mut (dyn Write<Error = E> + '_),
    mut value: u64,
) -> Result<(), E> {
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
pub fn put_pad<E: embedded_io::Error>(
    writer: &mut (dyn Write<Error = E> + '_),
    mut value: u64,
) -> Result<(), E> {
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
pub fn read_custom_section<'a, E: embedded_io::Error, R: Read<Error = E>, T>(
    reader: &'a mut R,
    name_hash: &mut (dyn FnMut([u8; 32]) -> Option<T> + '_),
) -> Result<CustomSection<'a, R, T>, ReadExactError<E>> {
    loop {
        let mut ty = 0u8;
        reader.read_exact(slice::from_mut(&mut ty))?;
        let mut len = get(reader, None)?;
        match ty {
            0 => {
                let name_len = get(
                    reader,
                    Some(&mut || {
                        len -= 1;
                    }),
                )?;
                let mut hash = sha3::Sha3_256::default();
                for _ in 0..name_len {
                    reader.read_exact(slice::from_mut(&mut ty))?;
                    hash.update(&[ty]);
                }
                let hash: [u8; 32] = hash.finalize().into();
                if let Some(payload) = name_hash(hash) {
                    return Ok(CustomSection {
                        len,
                        reader,
                        payload,
                    });
                } else {
                    while len != 0 {
                        reader.read_exact(slice::from_mut(&mut ty))?;
                    }
                }
            }
            _ => {
                while len != 0 {
                    reader.read_exact(slice::from_mut(&mut ty))?;
                }
            }
        }
    }
}
// #[non_exhaustive]
pub struct CustomSection<'a, R, T = ()> {
    len: u64,
    reader: &'a mut R,
    pub payload: T,
}
impl<'a, R: ErrorType, T> ErrorType for CustomSection<'a, R, T> {
    type Error = R::Error;
}
impl<'a, R: Read, T> Read for CustomSection<'a, R, T> {
    fn read(&mut self, mut buf: &mut [u8]) -> Result<usize, Self::Error> {
        if buf.len() as u64 > self.len {
            buf = &mut buf[..(self.len as usize)];
        }
        let a = self.reader.read(buf)?;
        self.len -= (a as u64);
        return Ok(a);
    }
}
impl<'a, R, T> CustomSection<'a, R, T> {
    pub fn len(&self) -> u64 {
        return self.len;
    }
    pub fn take(self) -> Result<(&'a mut R, T), Self> {
        match self.len {
            0 => Ok((self.reader, self.payload)),
            _ => Err(self),
        }
    }
}
#[macro_export]
macro_rules! read_custom_section_with_name {
    ($a:expr, $b:expr) => {
        $crate::module::read_custom_section($a, &mut |a| a == $crate::__::sha3_literal!($b))
    };
}
