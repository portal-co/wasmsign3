#![no_std]
#![feature(generic_const_exprs)]
pub mod __ {
    pub use core;
    pub use sha3_literal::sha3_literal;
}
use core::array::from_fn;

use embedded_io::Write;
use slh_dsa::{ParameterSet, Shake128s, Signature, SignatureLen, SigningKey, VerifyingKey, VerifyingKeyLen};
use typenum::Unsigned;

use crate::module::{put, put_pad};
#[derive(Clone, Debug)]
#[repr(transparent)]
pub struct WS3Sig(pub Signature<Shake128s>);
#[derive(Clone, Debug)]
#[repr(transparent)]
pub struct WS3Pk(pub VerifyingKey<Shake128s>);
#[derive(Clone, Debug)]
#[repr(transparent)]
pub struct WS3Sk(pub SigningKey<Shake128s>);
pub fn split_off(a: &[u8]) -> Option<(&[u8], WS3Sig)> {
    let (a, b) = a.split_at_checked(
        a.len()
            .wrapping_sub(14 + <<Shake128s as SignatureLen>::SigLen as Unsigned>::USIZE),
    )?;
    let (_, b) = b.split_at_checked(14)?;

    Some((a, WS3Sig(Signature::try_from(b).ok()?)))
}
pub fn render(
    a: &WS3Sig,
) -> [u8; { 14 + <<Shake128s as SignatureLen>::SigLen as Unsigned>::USIZE }] {
    let mut d: [u8; { 14 + <<Shake128s as SignatureLen>::SigLen as Unsigned>::USIZE }] =
        from_fn(|_| 0u8);
    d[0] = 0;
    let v = (d.len() - 3) as u64;
    put(&mut &mut d[1..], v).unwrap();
    d[3] = 10;
    d[4..(4 + 10)].copy_from_slice(b"signature2");
    d[14..].copy_from_slice(&a.0.to_bytes());
    d
}
pub fn render_assertion<const N: usize>(
    sig: [Option<&WS3Sig>; N],
    pk: &WS3Pk,
) -> [u8; {
    21 + <<Shake128s as VerifyingKeyLen>::VkLen as Unsigned>::USIZE
        + <<Shake128s as SignatureLen>::SigLen as Unsigned>::USIZE * N
}] {
    let mut d: [u8; {
        21 + <<Shake128s as VerifyingKeyLen>::VkLen as Unsigned>::USIZE
            + <<Shake128s as SignatureLen>::SigLen as Unsigned>::USIZE * N
    }] = from_fn(|_| 0u8);
    d[0] = 0;
    let v = (d.len() - 11) as u64;
    let mut w = &mut d[1..];
    put_pad(&mut w, v).unwrap();
    // d[3] = 10;
    w.write_all(&[10]).unwrap();
    w.write_all(b"assertion2").unwrap();
    w.write_all(&pk.0.to_bytes()).unwrap();
    for s in sig.iter() {
        let b = match s.as_deref() {
            Some(a) => a.0.to_bytes(),
            None => Default::default(),
        };
        w.write_all(&b).unwrap();
    }
    d
}
pub mod module;
