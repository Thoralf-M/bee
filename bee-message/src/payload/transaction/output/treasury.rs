// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{payload::transaction::constants::IOTA_SUPPLY, Error};

use bee_common::packable::{Packable, Read, Write};

use serde::{Deserialize, Serialize};

pub(crate) const TREASURY_OUTPUT_TYPE: u8 = 2;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, Ord, PartialOrd)]
pub struct TreasuryOutput {
    amount: u64,
}

impl TreasuryOutput {
    pub fn new(amount: u64) -> Result<Self, Error> {
        if amount == 0 || amount > IOTA_SUPPLY {
            return Err(Error::InvalidAmount(amount));
        }

        Ok(Self { amount })
    }

    pub fn amount(&self) -> u64 {
        self.amount
    }
}

impl Packable for TreasuryOutput {
    type Error = Error;

    fn packed_len(&self) -> usize {
        self.amount.packed_len()
    }

    fn pack<W: Write>(&self, writer: &mut W) -> Result<(), Self::Error> {
        self.amount.pack(writer)?;

        Ok(())
    }

    fn unpack<R: Read + ?Sized>(reader: &mut R) -> Result<Self, Self::Error> {
        Self::new(u64::unpack(reader)?)
    }
}