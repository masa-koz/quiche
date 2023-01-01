// Copyright (C) 2018-2019, Cloudflare, Inc.
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

use std::ffi;
use std::ptr;
use std::slice;

use std::io::Write;

use libc::c_char;
use libc::c_int;
use libc::c_long;
use libc::c_uint;
use libc::c_void;

use crate::Error;
use crate::Result;

use crate::Connection;
use crate::ConnectionError;

use crate::crypto;
use crate::packet;

const TLS1_3_VERSION: u16 = 0x0304;
const TLS_ALERT_ERROR: u64 = 0x100;
const INTERNAL_ERROR: u64 = 0x01;

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct SSL_METHOD(c_void);

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct SSL_CTX(c_void);

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct SSL(c_void);

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct SSL_CIPHER(c_void);

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct SSL_SESSION(c_void);

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct X509_VERIFY_PARAM(c_void);

#[allow(non_camel_case_types)]
#[repr(transparent)]
#[cfg(windows)]
struct X509_STORE(c_void);

#[allow(non_camel_case_types)]
#[repr(transparent)]
#[cfg(windows)]
struct X509(c_void);

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct STACK_OF(c_void);

#[allow(non_camel_case_types)]
#[repr(transparent)]
struct CRYPTO_BUFFER(c_void);

#[repr(C)]
#[allow(non_camel_case_types)]
struct SSL_QUIC_METHOD {
    set_read_secret: extern fn(
        ssl: *mut SSL,
        level: crypto::Level,
        cipher: *const SSL_CIPHER,
        secret: *const u8,
        secret_len: usize,
    ) -> c_int,

    set_write_secret: extern fn(
        ssl: *mut SSL,
        level: crypto::Level,
        cipher: *const SSL_CIPHER,
        secret: *const u8,
        secret_len: usize,
    ) -> c_int,

    add_handshake_data: extern fn(
        ssl: *mut SSL,
        level: crypto::Level,
        data: *const u8,
        len: usize,
    ) -> c_int,

    flush_flight: extern fn(ssl: *mut SSL) -> c_int,

    send_alert:
        extern fn(ssl: *mut SSL, level: crypto::Level, alert: u8) -> c_int,
}

lazy_static::lazy_static! {
}

static QUICHE_STREAM_METHOD: SSL_QUIC_METHOD = SSL_QUIC_METHOD {
    set_read_secret,
    set_write_secret,
    add_handshake_data,
    flush_flight,
    send_alert,
};

pub struct Context(*mut SSL_CTX);

impl Context {
    pub fn new() -> Result<Context> {
        unimplemented!();
    }

    pub fn new_handshake(&mut self) -> Result<Handshake> {
        unimplemented!();
    }

    pub fn load_verify_locations_from_file(&mut self, file: &str) -> Result<()> {
        unimplemented!();
    }

    pub fn load_verify_locations_from_directory(
        &mut self, path: &str,
    ) -> Result<()> {
        unimplemented!();
    }

    pub fn use_certificate_chain_file(&mut self, file: &str) -> Result<()> {
        unimplemented!();
    }

    pub fn use_privkey_file(&mut self, file: &str) -> Result<()> {
        unimplemented!();
    }

    #[cfg(not(windows))]
    fn load_ca_certs(&mut self) -> Result<()> {
        unimplemented!();
    }

    #[cfg(windows)]
    fn load_ca_certs(&mut self) -> Result<()> {
        unimplemented!();
    }

    fn set_session_callback(&mut self) {
        unimplemented!();
    }

    pub fn set_verify(&mut self, verify: bool) {
        unimplemented!();
    }

    pub fn enable_keylog(&mut self) {
        unimplemented!();
    }

    pub fn set_alpn(&mut self, v: &[&[u8]]) -> Result<()> {
        unimplemented!();
    }

    pub fn set_ticket_key(&mut self, key: &[u8]) -> Result<()> {
        unimplemented!();
    }

    pub fn set_early_data_enabled(&mut self, enabled: bool) {
        unimplemented!();
    }
}

// NOTE: These traits are not automatically implemented for Context due to the
// raw pointer it wraps. However, the underlying data is not aliased (as Context
// should be its only owner), and there is no interior mutability, as the
// pointer is not accessed directly outside of this module, and the Context
// object API should preserve Rust's borrowing guarantees.
unsafe impl std::marker::Send for Context {}
unsafe impl std::marker::Sync for Context {}

impl Drop for Context {
    fn drop(&mut self) {
        unimplemented!();
    }
}

pub struct Handshake {
    /// Raw pointer
    ptr: *mut SSL,
    /// SSL_process_quic_post_handshake should be called when whenever
    /// SSL_provide_quic_data is called to process the provided data.
    provided_data_outstanding: bool,
}

impl Handshake {
    #[cfg(feature = "ffi")]
    pub unsafe fn from_ptr(ssl: *mut c_void) -> Handshake {
        unimplemented!();
    }

    fn new(ptr: *mut SSL) -> Handshake {
        unimplemented!();
    }

    pub fn get_error(&self, ret_code: c_int) -> c_int {
        unimplemented!();
    }

    pub fn init(&mut self, is_server: bool) -> Result<()> {
        unimplemented!();
    }

    pub fn use_legacy_codepoint(&mut self, use_legacy: bool) {
        unimplemented!();
    }

    pub fn set_state(&mut self, is_server: bool) {
        unimplemented!();
    }

    pub fn set_ex_data<T>(&mut self, idx: c_int, data: *const T) -> Result<()> {
        unimplemented!();
    }

    pub fn set_quic_method(&mut self) -> Result<()> {
        unimplemented!();
    }

    pub fn set_quic_early_data_context(&mut self, context: &[u8]) -> Result<()> {
        unimplemented!();
    }

    pub fn set_min_proto_version(&mut self, version: u16) {
        unimplemented!();
    }

    pub fn set_max_proto_version(&mut self, version: u16) {
        unimplemented!();
    }

    pub fn set_quiet_shutdown(&mut self, mode: bool) {
        unimplemented!();
    }

    pub fn set_host_name(&mut self, name: &str) -> Result<()> {
        unimplemented!();
    }

    pub fn set_quic_transport_params(&mut self, buf: &[u8]) -> Result<()> {
        unimplemented!();
    }

    #[cfg(test)]
    pub fn set_options(&mut self, opts: u32) {
        unimplemented!();
    }

    pub fn quic_transport_params(&self) -> &[u8] {
        unimplemented!();
    }

    pub fn alpn_protocol(&self) -> &[u8] {
        unimplemented!();
    }

    pub fn server_name(&self) -> Option<&str> {
        unimplemented!();
    }

    pub fn set_session(&mut self, session: &[u8]) -> Result<()> {
        unimplemented!();
    }

    pub fn provide_data(
        &mut self, level: crypto::Level, buf: &[u8],
    ) -> Result<()> {
        unimplemented!();
    }

    pub fn do_handshake(&mut self, ex_data: &mut ExData) -> Result<()> {
        unimplemented!();
    }

    pub fn process_post_handshake(&mut self, ex_data: &mut ExData) -> Result<()> {
        unimplemented!();
    }

    pub fn reset_early_data_reject(&mut self) {
        unimplemented!();
    }

    pub fn write_level(&self) -> crypto::Level {
        unimplemented!();
    }

    pub fn cipher(&self) -> Option<crypto::Algorithm> {
        unimplemented!();
    }

    pub fn curve(&self) -> Option<String> {
        unimplemented!();
    }

    pub fn sigalg(&self) -> Option<String> {
        unimplemented!();
    }

    pub fn peer_cert_chain(&self) -> Option<Vec<&[u8]>> {
        unimplemented!();
    }

    pub fn peer_cert(&self) -> Option<&[u8]> {
        unimplemented!();
    }

    pub fn is_completed(&self) -> bool {
        unimplemented!();
    }

    pub fn is_resumed(&self) -> bool {
        unimplemented!();
    }

    pub fn is_in_early_data(&self) -> bool {
        unimplemented!();
    }

    pub fn clear(&mut self) -> Result<()> {
        unimplemented!();
    }

    fn as_ptr(&self) -> *const SSL {
        unimplemented!();
    }

    fn as_mut_ptr(&mut self) -> *mut SSL {
        unimplemented!();
    }

    fn map_result_ssl(&mut self, bssl_result: c_int) -> Result<()> {
        unimplemented!();
    }

    fn set_transport_error(&mut self, ex_data: &mut ExData, bssl_result: c_int) {
        unimplemented!();
    }
}

// NOTE: These traits are not automatically implemented for Handshake due to the
// raw pointer it wraps. However, the underlying data is not aliased (as
// Handshake should be its only owner), and there is no interior mutability, as
// the pointer is not accessed directly outside of this module, and the
// Handshake object API should preserve Rust's borrowing guarantees.
unsafe impl std::marker::Send for Handshake {}
unsafe impl std::marker::Sync for Handshake {}

impl Drop for Handshake {
    fn drop(&mut self) {
        unimplemented!();
    }
}

pub struct ExData<'a> {
    pub application_protos: &'a Vec<Vec<u8>>,

    pub pkt_num_spaces: &'a mut [packet::PktNumSpace; packet::Epoch::count()],

    pub session: &'a mut Option<Vec<u8>>,

    pub local_error: &'a mut Option<crate::ConnectionError>,

    pub keylog: Option<&'a mut Box<dyn std::io::Write + Send + Sync>>,

    pub trace_id: &'a str,

    pub is_server: bool,
}

fn get_ex_data_from_ptr<'a, T>(ptr: *mut SSL, idx: c_int) -> Option<&'a mut T> {
    unimplemented!();
}

fn get_cipher_from_ptr(cipher: *const SSL_CIPHER) -> Result<crypto::Algorithm> {
    unimplemented!();
}

extern fn set_read_secret(
    ssl: *mut SSL, level: crypto::Level, cipher: *const SSL_CIPHER,
    secret: *const u8, secret_len: usize,
) -> c_int {
    unimplemented!();
}

extern fn set_write_secret(
    ssl: *mut SSL, level: crypto::Level, cipher: *const SSL_CIPHER,
    secret: *const u8, secret_len: usize,
) -> c_int {
    unimplemented!();
}

extern fn add_handshake_data(
    ssl: *mut SSL, level: crypto::Level, data: *const u8, len: usize,
) -> c_int {
    unimplemented!();
}

extern fn flush_flight(_ssl: *mut SSL) -> c_int {
    unimplemented!();
}

extern fn send_alert(ssl: *mut SSL, level: crypto::Level, alert: u8) -> c_int {
    unimplemented!();
}

extern fn keylog(ssl: *mut SSL, line: *const c_char) {
    unimplemented!();
}

extern fn select_alpn(
    ssl: *mut SSL, out: *mut *const u8, out_len: *mut u8, inp: *mut u8,
    in_len: c_uint, _arg: *mut c_void,
) -> c_int {
    unimplemented!();
}

extern fn new_session(ssl: *mut SSL, session: *mut SSL_SESSION) -> c_int {
    unimplemented!();
}

fn map_result(bssl_result: c_int) -> Result<()> {
    unimplemented!();
}

fn map_result_zero_is_success(bssl_result: c_int) -> Result<()> {
    unimplemented!();
}

fn map_result_ptr<'a, T>(bssl_result: *const T) -> Result<&'a T> {
    unimplemented!();
}

fn log_ssl_error() {
    unimplemented!();
}