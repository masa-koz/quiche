// Copyright (C) 2022, Cloudflare, Inc.
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
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use crate::Error;
use crate::Result;

use std::collections::VecDeque;

use std::net::SocketAddr;

#[derive(Debug)]
pub enum PathState {
    Validating,
    Active,
    Closed,
}

/// A structure representing path.
#[derive(Debug)]
pub struct PathEntry {
    /// Identifier.
    pub id: u64,
    /// The state of this path.
    pub state: PathState,
    /// A peer address.
    pub peer_addr: SocketAddr,
    /// A local address.
    pub local_addr: SocketAddr,
    /// Whether a peer address has been verified.
    pub verified_peer_addr: bool,
    challenge: Option<[u8; 8]>,
    responses: VecDeque<[u8; 8]>,
}

#[derive(Default)]
struct PathEntries {
    /// All the paths recognized.
    entries: VecDeque<PathEntry>,
    /// Next path identifier to use.
    next_path_id: u64,
}

impl PathEntries {
    pub fn new() -> PathEntries {
        PathEntries {
            ..Default::default()
        }
    }

    fn add(
        &mut self, peer_addr: SocketAddr, verified_peer_addr: bool, local_addr: SocketAddr
    ) -> Result<u64> {
        let id = self.next_path_id;

        if let Some(_) = self.entries.iter().find(|e| e.peer_addr == peer_addr && e.local_addr == local_addr) {
            return Err(Error::InvalidState);
        }

        self.entries.push_back(PathEntry {
            id,
            state: PathState::Validating,
            peer_addr,
            local_addr,
            verified_peer_addr,
            challenge: None,
            responses: VecDeque::new()
        });

        self.next_path_id += 1;

        Ok(id)
    }

    fn activate(
        &mut self, peer_addr: SocketAddr, local_addr: SocketAddr, challenge: Option<[u8; 8]>
    ) -> Result<u64> {
        if let Some(e) = self.entries.iter_mut().find(|e| e.peer_addr == peer_addr && e.local_addr == local_addr) {
            if e.challenge == challenge {
                e.state = PathState::Active;
                return Ok(e.id);
            }
        }
        Err(Error::InvalidState)
    }

    fn receive_path_challenge(
        &mut self, peer_addr: SocketAddr, local_addr: SocketAddr, challenge: [u8; 8]
    ) -> Result<u64> {
        if let Some(e) = self.entries.iter_mut().find(|e| e.peer_addr == peer_addr && e.local_addr == local_addr) {
            e.responses.push_back(challenge);
            return Ok(e.id);
        }
        Err(Error::InvalidState)
    }

    fn retransmit_path_challenge(&self, challenge: [u8; 8]) -> Result<u64> {
        let res = self.entries.iter().find(|e| {
            if let Some(challenge1) = e.challenge {
                challenge1 == challenge
            } else {
                false
            }
        });
        if let Some(e) = res {
            Ok(e.id)
        } else {
            Err(Error::InvalidState)
        }
    }
}

struct PeerAddressEntry {
    addr: SocketAddr,
    verified: bool,
}

#[derive(Default)]
pub struct PathManagement {
    paths: PathEntries,
    /// All the peer addresses.
    peer_addrs: VecDeque<PeerAddressEntry>,
    /// All the local addresses.
    local_addrs: VecDeque<SocketAddr>,
    validating_paths: VecDeque<u64>,
    responding_paths: VecDeque<u64>,
}

impl PathManagement {
    pub fn new() -> PathManagement {
        PathManagement {
            ..Default::default()
        }
    }

    pub fn default_path(&self) -> Result<&PathEntry> {
        self.paths.entries.front().ok_or(Error::InvalidState)
    }

    pub fn add_peer_addr(&mut self, peer_addr: SocketAddr) -> Result<Vec<u64>> {
        if let Some(e) = self.peer_addrs.iter().find(|e| e.addr == peer_addr) {
            return Err(Error::InvalidState);
        }
        self.peer_addrs.push_back(PeerAddressEntry {addr: peer_addr, verified: false});
        let mut new_path_ids = Vec::new();
        for local_addr in &self.local_addrs {
            if let Ok(path_id) = self.paths.add(peer_addr, false, *local_addr) {
                self.validating_paths.push_back(path_id);
                new_path_ids.push(path_id);
            }
        }
        Ok(new_path_ids)
    }

    pub fn add_local_addr(&mut self, local_addr: SocketAddr) -> Result<Vec<u64>> {
        if let Some(e) = self.local_addrs.iter().find(|&&e| e == local_addr) {
            return Err(Error::InvalidState);
        }
        self.local_addrs.push_back(local_addr);
        let mut new_path_ids = Vec::new();
        for e in &self.peer_addrs {
            if let Ok(path_id) = self.paths.add(e.addr, e.verified, local_addr) {
                self.validating_paths.push_back(path_id);
                new_path_ids.push(path_id);
            }
        }
        Ok(new_path_ids)
    }

    pub fn verify_peer_addr(&mut self, peer_addr: SocketAddr) -> Result<()> {
        for e in self.peer_addrs.iter_mut() {
            if e.addr == peer_addr {
                e.verified = true;
            }
        }
        for e in self.paths.entries.iter_mut() {
            if e.peer_addr == peer_addr {
                e.verified_peer_addr = true;
            }
        }
        Ok(())
    }

    pub fn activate_path(
        &mut self, peer_addr: SocketAddr, local_addr: SocketAddr, challenge: Option<[u8; 8]>
    ) -> Result<u64> {
        self.paths.activate(peer_addr, local_addr, challenge)
    }

    pub fn receive_path_challenge(
        &mut self, peer_addr: SocketAddr, local_addr: SocketAddr, challenge: [u8; 8]
    ) -> Result<u64> {
        let path_id = self.paths.receive_path_challenge(peer_addr, local_addr, challenge)?;
        self.responding_paths.push_back(path_id);
        Ok(path_id)
    }

    pub fn retransmit_path_challenge(&self, challenge: [u8; 8]) -> Result<u64> {
        let path_id = self.paths.retransmit_path_challenge(challenge)?;
        self.validating_paths.push_back(path_id);
        Ok(path_id)
    }

    pub fn get_path_response_frame(&mut self) -> Result<frame::Frame> {
        if let Some(e) = self.responses.iter().find(|&&e| e.0 == 0) {
        }
    }
}