// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod ed25519;

use ed25519::ED25519_ADDRESS_TYPE;
pub use ed25519::{Ed25519Address, ED25519_ADDRESS_LENGTH};

use crate::{payload::transaction::SignatureUnlock, Error};

use bee_common::packable::{Packable, Read, Write};

use bech32::FromBase32;
use serde::{Deserialize, Serialize};

use alloc::string::String;
use core::{convert::TryFrom, str::FromStr};

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize, Ord, PartialOrd, Hash)]
#[serde(tag = "type", content = "data")]
pub enum Address {
    Ed25519(Ed25519Address),
}

impl From<Ed25519Address> for Address {
    fn from(address: Ed25519Address) -> Self {
        Self::Ed25519(address)
    }
}

impl TryFrom<&str> for Address {
    type Error = Error;
    fn try_from(address: &str) -> Result<Self, Self::Error> {
        if let Ok(address) = Ed25519Address::from_str(&address) {
            Ok(Address::Ed25519(address))
        } else {
            Address::try_from_bech32(address)
        }
    }
}

impl TryFrom<String> for Address {
    type Error = Error;
    fn try_from(address: String) -> Result<Self, Self::Error> {
        if let Ok(address) = Ed25519Address::from_str(&address) {
            Ok(Address::Ed25519(address))
        } else {
            Address::try_from_bech32(&address)
        }
    }
}

impl AsRef<[u8]> for Address {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Ed25519(address) => address.as_ref(),
        }
    }
}

impl Address {
    pub fn try_from_bech32(addr: &str) -> Result<Self, Error> {
        match bech32::decode(&addr) {
            Ok((_hrp, data)) => {
                let bytes = Vec::<u8>::from_base32(&data).map_err(|_| Error::InvalidAddress)?;
                Ok(Self::unpack(&mut bytes.as_slice()).map_err(|_| Error::InvalidAddress)?)
            }
            Err(_) => Err(Error::InvalidAddress),
        }
    }

    pub fn to_bech32(&self, hrp: &str) -> String {
        match self {
            Address::Ed25519(address) => address.to_bech32(hrp),
        }
    }

    pub fn verify(&self, msg: &[u8], signature: &SignatureUnlock) -> bool {
        match self {
            Address::Ed25519(address) => {
                let SignatureUnlock::Ed25519(signature) = signature;
                address.verify(msg, signature)
            }
        }
    }
}

impl Packable for Address {
    type Error = Error;

    fn packed_len(&self) -> usize {
        match self {
            Self::Ed25519(address) => ED25519_ADDRESS_TYPE.packed_len() + address.packed_len(),
        }
    }

    fn pack<W: Write>(&self, writer: &mut W) -> Result<(), Self::Error> {
        match self {
            Self::Ed25519(address) => {
                ED25519_ADDRESS_TYPE.pack(writer)?;
                address.pack(writer)?;
            }
        }
        Ok(())
    }

    fn unpack<R: Read + ?Sized>(reader: &mut R) -> Result<Self, Self::Error> {
        Ok(match u8::unpack(reader)? {
            ED25519_ADDRESS_TYPE => Self::Ed25519(Ed25519Address::unpack(reader)?),
            t => return Err(Self::Error::InvalidAddressType(t)),
        })
    }
}
