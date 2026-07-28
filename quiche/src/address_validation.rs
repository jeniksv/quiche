// Copyright (C) 2018, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

use std::collections::HashSet;
use std::collections::VecDeque;

use crate::Error;
use crate::Result;
use crate::MAX_ADDRESS_VALIDATION_TOKEN_LEN;

/// Manages address validation tokens sent in NEW_TOKEN frames.
#[derive(Debug)]
pub struct AddressValidationTokens {
    pending: VecDeque<Vec<u8>>,

    retransmits: VecDeque<Vec<u8>>,

    in_flight: HashSet<Vec<u8>>,
}

impl AddressValidationTokens {
    pub fn new() -> Self {
        Self {
            pending: VecDeque::new(),
            retransmits: VecDeque::new(),
            in_flight: HashSet::new(),
        }
    }

    pub fn push(&mut self, token: &[u8]) -> Result<()> {
        if token.is_empty() {
            return Err(Error::InvalidFrame);
        }

        if token.len() > MAX_ADDRESS_VALIDATION_TOKEN_LEN {
            return Err(Error::BufferTooShort);
        }

        if self.pending.iter().any(|queued| queued.as_slice() == token) ||
            self.retransmits
                .iter()
                .any(|queued| queued.as_slice() == token) ||
            self.in_flight.contains(token)
        {
            return Err(Error::InvalidFrame);
        }

        self.pending.push_back(token.to_vec());

        Ok(())
    }

    pub fn on_packet_acked(&mut self, token: &[u8]) {
        self.in_flight.remove(token);

        if let Some(pos) = self
            .retransmits
            .iter()
            .position(|queued| queued.as_slice() == token)
        {
            let _ = self.retransmits.remove(pos);
        }
    }

    pub fn on_packet_lost(&mut self, token: Vec<u8>) {
        if !self.in_flight.remove(token.as_slice()) {
            return;
        }

        if !self.retransmits.iter().any(|queued| queued == &token) {
            self.retransmits.push_back(token);
        }
    }

    pub fn next(&self) -> Option<&[u8]> {
        self.retransmits
            .front()
            .or_else(|| self.pending.front())
            .map(Vec::as_slice)
    }

    pub fn on_packet_sent(&mut self) {
        if let Some(token) = self.pop_next() {
            self.in_flight.insert(token);
        }
    }

    fn pop_next(&mut self) -> Option<Vec<u8>> {
        self.retransmits
            .pop_front()
            .or_else(|| self.pending.pop_front())
    }

    pub fn has_pending(&self) -> bool {
        !self.retransmits.is_empty() || !self.pending.is_empty()
    }
}
