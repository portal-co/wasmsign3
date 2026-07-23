//! V0.1 signing target for `portal.wasm.meta.v1` manifests.
//!
//! The target is deliberately source-neutral.  A manifest can be used by a
//! consumer without a signature; this module only supplies the binding an
//! embedding requests when it chooses `RequireSignature`.

extern crate alloc;

use alloc::vec::Vec;
use core::convert::TryInto;
use slh_dsa::signature::{Signer, Verifier};

use crate::{WS3Pk, WS3Sig, WS3Sk};

pub const TARGET_SECTION_NAME: &str = "portal.wasmsign3.target.v1";
pub const SIGNATURE_SECTION_NAME: &str = "portal.wasmsign3.signature.v1";
const MAGIC: [u8; 4] = *b"WST3";
const VERSION: u8 = 1;

/// The four digests that bind a v0.1 semantic manifest to its WASM module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WsmmDigests {
    pub code: [u8; 32],
    pub data: [u8; 32],
    /// Includes table declarations and every element segment/initializer.
    pub interface: [u8; 32],
    pub semantic: [u8; 32],
}

/// Canonical signer input and target-section payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WsmmSigningTargetV1 {
    pub digests: WsmmDigests,
    pub policy_id: Vec<u8>,
    pub signer_context: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetError {
    Malformed,
    Version(u8),
    Length,
    Signature,
}

impl WsmmSigningTargetV1 {
    pub fn new(digests: WsmmDigests, policy_id: Vec<u8>, signer_context: Vec<u8>) -> Result<Self, TargetError> {
        if policy_id.len() > u16::MAX as usize || signer_context.len() > u16::MAX as usize {
            return Err(TargetError::Length);
        }
        Ok(Self { digests, policy_id, signer_context })
    }

    /// Bytes signed by SLH-DSA. They are also the target section payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 1 + 128 + 4 + self.policy_id.len() + self.signer_context.len());
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.digests.code);
        out.extend_from_slice(&self.digests.data);
        out.extend_from_slice(&self.digests.interface);
        out.extend_from_slice(&self.digests.semantic);
        put_bytes(&mut out, &self.policy_id);
        put_bytes(&mut out, &self.signer_context);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TargetError> {
        if bytes.len() < 4 + 1 + 128 || bytes[..4] != MAGIC { return Err(TargetError::Malformed); }
        if bytes[4] != VERSION { return Err(TargetError::Version(bytes[4])); }
        let mut pos = 5;
        let take_digest = |pos: &mut usize| -> Result<[u8; 32], TargetError> {
            let end = pos.checked_add(32).ok_or(TargetError::Malformed)?;
            let digest = bytes.get(*pos..end).ok_or(TargetError::Malformed)?.try_into().map_err(|_| TargetError::Malformed)?;
            *pos = end;
            Ok(digest)
        };
        let digests = WsmmDigests {
            code: take_digest(&mut pos)?, data: take_digest(&mut pos)?,
            interface: take_digest(&mut pos)?, semantic: take_digest(&mut pos)?,
        };
        let policy_id = take_bytes(bytes, &mut pos)?;
        let signer_context = take_bytes(bytes, &mut pos)?;
        if pos != bytes.len() { return Err(TargetError::Malformed); }
        Self::new(digests, policy_id, signer_context)
    }

    pub fn sign(&self, key: &WS3Sk) -> Result<WS3Sig, TargetError> {
        key.0.try_sign(&self.encode()).map(WS3Sig).map_err(|_| TargetError::Signature)
    }

    pub fn verify(&self, key: &WS3Pk, signature: &WS3Sig) -> Result<(), TargetError> {
        key.0.verify(&self.encode(), &signature.0).map_err(|_| TargetError::Signature)
    }
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn take_bytes(bytes: &[u8], pos: &mut usize) -> Result<Vec<u8>, TargetError> {
    let end = pos.checked_add(2).ok_or(TargetError::Malformed)?;
    let len = u16::from_le_bytes(bytes.get(*pos..end).ok_or(TargetError::Malformed)?.try_into().map_err(|_| TargetError::Malformed)?) as usize;
    *pos = end;
    let end = pos.checked_add(len).ok_or(TargetError::Malformed)?;
    let value = bytes.get(*pos..end).ok_or(TargetError::Malformed)?.to_vec();
    *pos = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_round_trip_binds_table_element_interface_digest() {
        let digests = WsmmDigests { code: [1; 32], data: [2; 32], interface: [3; 32], semantic: [4; 32] };
        let target = WsmmSigningTargetV1::new(digests, b"resource-layout/v0.1".to_vec(), Vec::from([9])).unwrap();
        let bytes = target.encode();
        assert_eq!(WsmmSigningTargetV1::decode(&bytes).unwrap(), target);
        let mut changed = target.clone();
        changed.digests.interface[0] ^= 1;
        assert_ne!(changed.encode(), bytes);
    }
}