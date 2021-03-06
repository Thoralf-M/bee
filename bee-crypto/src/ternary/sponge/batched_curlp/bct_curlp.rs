// Copyright 2020 IOTA Stiftung
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::ternary::{
    sponge::{
        batched_curlp::{
            bct::{BCTrit, BCTritBuf},
            HIGH_BITS,
        },
        CurlPRounds,
    },
    HASH_LENGTH,
};

pub(crate) struct BCTCurlP {
    rounds: CurlPRounds,
    state: BCTritBuf,
    scratch_pad: BCTritBuf,
}

impl BCTCurlP {
    #[allow(clippy::assertions_on_constants)]
    pub(crate) fn new(rounds: CurlPRounds) -> Self {
        // Ensure that changing the hash length will not cause undefined behaviour.
        assert!(3 * HASH_LENGTH > 728);
        Self {
            rounds,
            state: BCTritBuf::filled(HIGH_BITS, 3 * HASH_LENGTH),
            scratch_pad: BCTritBuf::filled(HIGH_BITS, 3 * HASH_LENGTH),
        }
    }

    pub(crate) fn reset(&mut self) {
        self.state.fill(HIGH_BITS);
    }

    pub(crate) fn transform(&mut self) {
        let mut scratch_pad_index = 0;

        // All the unchecked accesses here are guaranteed to be safe by the assertion inside `new`.
        for _round in 0..self.rounds as usize {
            self.scratch_pad.copy_from_slice(&self.state);

            let BCTrit(mut alpha, mut beta) = unsafe { *self.scratch_pad.get_unchecked(scratch_pad_index) };

            scratch_pad_index += 364;

            let mut temp = unsafe { *self.scratch_pad.get_unchecked(scratch_pad_index) };

            let delta = beta ^ temp.lo();

            *unsafe { self.state.get_unchecked_mut(0) } = BCTrit(!(delta & alpha), delta | (alpha ^ temp.hi()));

            let mut state_index = 1;

            while state_index < self.state.len() {
                scratch_pad_index += 364;

                alpha = temp.lo();
                beta = temp.hi();
                temp = unsafe { *self.scratch_pad.get_unchecked(scratch_pad_index) };

                let delta = beta ^ temp.lo();

                *unsafe { self.state.get_unchecked_mut(state_index) } =
                    BCTrit(!(delta & alpha), delta | (alpha ^ temp.hi()));

                state_index += 1;

                scratch_pad_index -= 365;

                alpha = temp.lo();
                beta = temp.hi();
                temp = unsafe { *self.scratch_pad.get_unchecked(scratch_pad_index) };

                let delta = beta ^ temp.lo();

                *unsafe { self.state.get_unchecked_mut(state_index) } =
                    BCTrit(!(delta & alpha), delta | (alpha ^ temp.hi()));

                state_index += 1;
            }
        }
    }

    pub(crate) fn absorb(&mut self, bc_trits: &BCTritBuf) {
        let mut length = bc_trits.len();
        let mut offset = 0;

        loop {
            let length_to_copy = if length < HASH_LENGTH { length } else { HASH_LENGTH };
            // This is safe as `length_to_copy <= HASH_LENGTH`.
            unsafe { self.state.get_unchecked_mut(0..length_to_copy) }
                .copy_from_slice(unsafe { bc_trits.get_unchecked(offset..offset + length_to_copy) });

            self.transform();

            if length <= length_to_copy {
                break;
            } else {
                offset += length_to_copy;
                length -= length_to_copy;
            }
        }
    }

    // This method shouldn't assume that `result` has any particular content, just that it has an
    // adequate size.
    pub(crate) fn squeeze_into(&mut self, result: &mut BCTritBuf) {
        let trit_count = result.len();

        let hash_count = trit_count / HASH_LENGTH;

        for i in 0..hash_count {
            unsafe { result.get_unchecked_mut(i * HASH_LENGTH..(i + 1) * HASH_LENGTH) }
                .copy_from_slice(unsafe { self.state.get_unchecked(0..HASH_LENGTH) });

            self.transform();
        }

        let last = trit_count - hash_count * HASH_LENGTH;

        unsafe { result.get_unchecked_mut(trit_count - last..trit_count) }
            .copy_from_slice(unsafe { self.state.get_unchecked(0..last) });

        if trit_count % HASH_LENGTH != 0 {
            self.transform();
        }
    }
}
