//! Implementation of hcl.
use std::{
    ffi::{CStr, CString, c_char, c_int, c_uchar, c_ulonglong, c_void},
    marker::PhantomData,
    ptr::{null, null_mut},
};

/// Symmetric Key Size in bytes.
pub const KEYBYTES: usize = 32;
/// Nonce size in bytes.
pub const NONCEBYTES: usize = 24;
/// Amount of MACBytes in a symmetrically encrypted message.
pub const MACBYTES: usize = 16;

/// Size of a public key in bytes.
/// If you want to sign a message, use the SIGN_ equivalent.
pub const PUBLICKEYBYTES: usize = 32;
/// Size of a private key in bytes.
/// If you want to sign a message, use the SIGN_ equivalent.
pub const SECRETKEYBYTES: usize = 32;

/// Size of a public key that is used for signing in bytes.
pub const SIGN_PUBLICKEYBYTES: usize = 32;
/// Size of a private key that is used for signing in bytes.
pub const SIGN_SECRETKEYBYTES: usize = 32 + 32;

/// Length of a signature in bytes.
pub const SIGNBYTES: usize = 64;

pub const B64_VARIANT_NORMAL: c_int = 1;

/// A symmetric key.
pub type Key = [c_uchar; KEYBYTES];
/// A nonce.
pub type Nonce = [c_uchar; NONCEBYTES];

/// A public key. DO NOT use for signing.
pub type PublicKey = [c_uchar; PUBLICKEYBYTES];
/// A private key. DO NOT use for signing.
pub type SecretKey = [c_uchar; SECRETKEYBYTES];

/// A public key that can be used for signing.
pub type SignPublicKey = [c_uchar; SIGN_PUBLICKEYBYTES];
/// A private key that can be used for signing.
pub type SignSecretKey = [c_uchar; SIGN_SECRETKEYBYTES];

const PADDING_BLOCK_SIZE: usize = 16;

#[cfg(test)]
mod tests;

/// This struct exists to force intialization before use.
#[derive(Clone, Copy)]
pub struct Hcl {
    /// This field is here to prevent instantiation without calling new
    /// and thus preventing intialization of sodium.
    x: PhantomData<()>,
}

impl Hcl {
    pub fn new() -> Option<Self> {
        let init_code = unsafe { sodium_init() };

        if init_code >= 0 {
            Some(Hcl { x: PhantomData })
        } else {
            None
        }
    }

    /// Generate random bytes in a cryptographically secure way and
    /// store the result in bytes.
    pub fn gen_random_bytes(&self, bytes: &mut [u8]) {
        unsafe {
            randombytes_buf(bytes.as_mut_ptr() as *mut c_void, bytes.len());
        }
    }

    /// Sign the given bytes using the given secret_key and
    /// return bytes with the signature appended.
    pub fn sign_bytes(&self, bytes: &[u8], secret_key: SignSecretKey) -> Option<Box<[c_uchar]>> {
        let cap = bytes.len() + SIGNBYTES;

        let mut res_buf = vec![0; cap].into_boxed_slice();
        let mut res_len: c_ulonglong = 0;

        let res = unsafe {
            crypto_sign(
                res_buf.as_mut_ptr(),
                &mut res_len,
                bytes.as_ptr(),
                bytes.len() as c_ulonglong,
                secret_key.as_ptr(),
            )
        };
        if res == 0 { Some(res_buf) } else { None }
    }

    /// Sign a str using the given secret_key and
    /// return the string in bytes with the signature appended.
    pub fn sign_str(&self, s: &str, secret_key: SignSecretKey) -> Option<Box<[c_uchar]>> {
        self.sign_bytes(s.as_bytes(), secret_key)
    }

    /// Generate a new nonce in a cryptographically secure way.
    pub fn new_nonce(&self) -> Nonce {
        let mut res: Nonce = [0; NONCEBYTES];

        unsafe {
            randombytes_buf(res.as_mut_ptr() as *mut c_void, res.len());
        }

        res
    }

    /// Verify a signature and return signed without the signature bytes.
    pub fn sign_open(
        &self,
        signed: &[c_uchar],
        public_key: SignPublicKey,
    ) -> Option<Box<[c_uchar]>> {
        let cap_unsigned_message = signed.len() - SIGNBYTES;
        let mut res_buf = vec![0; cap_unsigned_message].into_boxed_slice();
        let mut res_len: c_ulonglong = 0;

        unsafe {
            let res = crypto_sign_open(
                res_buf.as_mut_ptr(),
                &mut res_len,
                signed.as_ptr(),
                signed.len() as u64,
                public_key.as_ptr(),
            );
            if res == 0 { Some(res_buf) } else { None }
        }
    }

    /// Sign a str and return ONLY the signature.
    pub fn sign_str_detached(&self, s: &str, secret_key: SignSecretKey) -> Option<Box<[c_uchar]>> {
        let cap = SIGNBYTES;
        let mut res_buf = vec![0; cap].into_boxed_slice();

        let res = unsafe {
            crypto_sign_detached(
                res_buf.as_mut_ptr(),
                null_mut(),
                s.as_ptr(),
                s.len() as u64,
                secret_key.as_ptr(),
            )
        };

        if res == 0 { Some(res_buf) } else { None }
    }

    /// Verify a detached signature.
    pub fn sign_detached_verify(&self, msg: &str, sig: &[u8], public_key: SignPublicKey) -> bool {
        unsafe {
            let res = crypto_sign_verify_detached(
                sig.as_ptr(),
                msg.as_ptr(),
                msg.len() as u64,
                public_key.as_ptr(),
            );
            res == 0
        }
    }

    /// Create a new ratchet.
    pub fn new_ratchet(&self, key: Key) -> Ratchet {
        Ratchet::new(key)
    }

    /// Calculate the length that a bin_len bytes would be in base 64.
    pub fn bin_length_to_base64_length(&self, bin_len: usize) -> usize {
        hcl_base64_encoded_len(bin_len)
    }

    /// Generate a random u32 in a cryptographically secure way, using a uniform distribution.
    pub fn random_uniform(&self, upper_bound: u32) -> u32 {
        unsafe { randombytes_uniform(upper_bound) }
    }

    /// Convert bin to a base64 encoded String.
    pub fn bin_to_base64(&self, bin: &[c_uchar]) -> Option<String> {
        let len = self.bin_length_to_base64_length(bin.len());
        let cap = len + 1; // content + 0 byte

        let mut buf: Box<[i8]> = vec![0; cap].into_boxed_slice();

        unsafe {
            sodium_bin2base64(
                buf.as_mut_ptr(),
                cap,
                bin.as_ptr(),
                bin.len(),
                B64_VARIANT_NORMAL,
            );
            match CStr::from_ptr(buf.as_ptr()).to_str() {
                Ok(s) => Some(s.to_string()),
                Err(_) => None,
            }
        }
    }

    /// Convert base64 to bytes.
    pub fn base64_to_bin(&self, b64: &str) -> Option<Box<[c_uchar]>> {
        let cap = b64.len() / 4 * 3;
        let mut bin_buf: Box<[c_uchar]> = vec![0; cap].into_boxed_slice();
        let mut actual_bin_len = 0;
        let s = CString::new(b64).unwrap();

        let res = unsafe {
            sodium_base642bin(
                bin_buf.as_mut_ptr(),
                cap,
                s.as_ptr(),
                b64.len(),
                null(),
                &mut actual_bin_len,
                null(),
                B64_VARIANT_NORMAL,
            )
        };
        if res == 0 {
            Some(bin_buf[..actual_bin_len].to_owned().into_boxed_slice())
        } else {
            None
        }
    }

    /// Generate a new symmetric key.
    pub fn gen_symmetric_key(&self) -> Key {
        let mut key = [0; KEYBYTES];
        unsafe {
            crypto_secretbox_keygen(key.as_mut_ptr());
        }
        key
    }

    /// Convert a string to a symmetric key using a salt.
    pub fn string_to_symmetric_key(&self, s: &str, salt: &str) -> Option<Key> {
        let mut key_buf = [0; KEYBYTES];

        let res = unsafe {
            crypto_kdf_hkdf_sha256_extract(
                key_buf.as_mut_ptr(),
                salt.as_ptr(),
                salt.len(),
                s.as_ptr(),
                s.len(),
            )
        };

        if res == 0 { Some(key_buf) } else { None }
    }

    /// Generate a new public/private keypair.
    /// This keypair is not intended to be used for signing.
    pub fn gen_keypair(&self) -> (PublicKey, SecretKey) {
        let mut public_key: PublicKey = [0; PUBLICKEYBYTES];
        let mut secret_key: SecretKey = [0; SECRETKEYBYTES];

        unsafe {
            crypto_box_keypair(public_key.as_mut_ptr(), secret_key.as_mut_ptr());
        }

        (public_key, secret_key)
    }

    /// Generate a new public/private keypair. Can be used for signing.
    pub fn gen_sign_keypair(&self) -> (SignPublicKey, SignSecretKey) {
        let mut public_key: SignPublicKey = [0; SIGN_PUBLICKEYBYTES];
        let mut secret_key: SignSecretKey = [0; SIGN_SECRETKEYBYTES];

        unsafe {
            crypto_sign_keypair(public_key.as_mut_ptr(), secret_key.as_mut_ptr());
        }

        (public_key, secret_key)
    }

    /// Encrypt a string given a symmetric key.
    pub fn string_symmetric_encrypt(&self, key: Key, s: &str) -> Option<Box<[c_uchar]>> {
        self.new_ratchet(key).encrypt_string(s)
    }

    /// Decrypt a string given a symmetric key.
    pub fn string_symmetric_decrypt(&self, key: Key, bytes: &[u8]) -> Option<String> {
        self.new_ratchet(key).decrypt_string(bytes)
    }
}

/// See Double Ratchet Algorithm for details
pub struct Ratchet {
    /// The current key of the ratchet.
    pub key: [c_uchar; KEYBYTES],
}

impl Ratchet {
    /// Creates a new ratchet
    fn new(key: Key) -> Self {
        Ratchet { key }
    }

    /// Encrypts a string by advancing the ratchet
    pub fn encrypt_string(&mut self, msg: &str) -> Option<Box<[c_uchar]>> {
        let mut padded_buf = vec![0; msg.len() + PADDING_BLOCK_SIZE];
        let mut padded_len: usize = 0;

        for (i, &b) in msg.as_bytes().iter().enumerate() {
            padded_buf[i] = b;
        }

        unsafe {
            if sodium_pad(
                &mut padded_len,
                padded_buf.as_mut_ptr(),
                msg.len(),
                PADDING_BLOCK_SIZE,
                padded_buf.len(),
            ) != 0
            {
                return None;
            }
        }

        let msg = &padded_buf[..padded_len];

        let (key, nonce) = self.advance()?;
        let ciphertext_len = msg.len() + MACBYTES;
        let mut result_buf = vec![0; ciphertext_len].into_boxed_slice();

        unsafe {
            if crypto_secretbox_easy(
                result_buf.as_mut_ptr(),
                msg.as_ptr(),
                msg.len(),
                nonce.as_ptr(),
                key.as_ptr(),
            ) != 0
            {
                return None;
            }
        }

        Some(result_buf)
    }

    /// Decrypts a string by advancing the ratchet
    pub fn decrypt_string(&mut self, bytes: &[u8]) -> Option<String> {
        let (key, nonce) = self.advance()?;
        let msg_len = bytes.len() - MACBYTES;
        let mut buf = vec![0; msg_len];

        unsafe {
            if crypto_secretbox_open_easy(
                buf.as_mut_ptr(),
                bytes.as_ptr(),
                bytes.len(),
                nonce.as_ptr(),
                key.as_ptr(),
            ) != 0
            {
                return None;
            }
        }

        let mut unpadded_len: usize = 0;
        unsafe {
            if sodium_unpad(
                &mut unpadded_len,
                buf.as_ptr(),
                buf.len(),
                PADDING_BLOCK_SIZE,
            ) != 0
            {
                return None;
            }
        }

        let buf = buf[..unpadded_len].to_vec();
        String::from_utf8(buf).ok()
    }

    /// Advances the ratchet
    pub fn advance(&mut self) -> Option<(Key, Nonce)> {
        const EXPAND_BUF_SIZE: usize = 88;

        let mut k = [0; KEYBYTES];
        let mut n = [0; NONCEBYTES];

        unsafe {
            let mut expand_buf = [0; EXPAND_BUF_SIZE];
            if crypto_kdf_hkdf_sha256_expand(
                expand_buf.as_mut_ptr(),
                expand_buf.len(),
                null(),
                0,
                self.key.as_ptr(),
            ) != 0
            {
                return None;
            }

            self.key.copy_from_slice(&expand_buf[..32]);
            k.copy_from_slice(&expand_buf[32..64]);
            n.copy_from_slice(&expand_buf[64..88]);
        }

        Some((k, n))
    }
}

/// Return the amount of bytes needed to store bin_len amount of bytes in base64
fn hcl_base64_encoded_len(bin_len: usize) -> usize {
    bin_len * 4
}

unsafe extern "C" {

    fn sodium_init() -> c_int;

    fn sodium_bin2base64(
        out: *mut c_char,
        out_len: usize,
        bin: *const c_uchar,
        bin_len: usize,
        variant: c_int,
    ) -> *mut c_char;

    fn sodium_base642bin(
        bin: *mut c_uchar,
        bin_max_len: usize,
        b64: *const c_char,
        b64_len: usize,
        ignore: *const c_char,
        bin_len: *mut usize,
        b64_end: *const *const c_char,
        variant: c_int,
    ) -> c_int;

    fn crypto_kdf_hkdf_sha256_expand(
        out: *mut c_uchar,
        out_len: usize,
        ctx: *const c_char,
        ctx_len: usize,
        key: *const c_uchar,
    ) -> c_int;

    fn crypto_kdf_hkdf_sha256_extract(
        out: *mut c_uchar,
        salt: *const c_uchar,
        salt_len: usize,
        ikm: *const c_uchar,
        ikm_len: usize,
    ) -> c_int;

    fn crypto_secretbox_easy(
        out: *mut c_uchar,
        input: *const c_uchar,
        input_len: usize,
        nonce: *const c_uchar,
        key: *const c_uchar,
    ) -> c_int;

    fn crypto_secretbox_open_easy(
        out: *mut c_uchar,
        ciphertext: *const c_uchar,
        ciphertext_len: usize,
        nonce: *const c_uchar,
        key: *const c_uchar,
    ) -> c_int;

    fn crypto_secretbox_keygen(out: *mut c_uchar);

    fn randombytes_uniform(upper_bound: u32) -> u32;

    fn randombytes_buf(buf: *mut c_void, size: usize);

    fn crypto_box_keypair(public_key: *mut c_uchar, secret_key: *mut c_uchar) -> c_int;

    fn crypto_sign_keypair(public_key: *mut c_uchar, secret_key: *mut c_uchar) -> c_int;

    fn crypto_sign(
        out: *mut c_uchar,
        out_len: *mut c_ulonglong,
        message: *const c_uchar,
        message_len: c_ulonglong,
        secret_key: *const c_uchar,
    ) -> c_int;

    fn crypto_sign_open(
        out: *mut c_uchar,
        out_len: *mut c_ulonglong,
        signed_message: *const c_uchar,
        signed_message_len: c_ulonglong,
        public_key: *const c_uchar,
    ) -> c_int;

    fn crypto_sign_detached(
        out_sig: *mut c_uchar,
        out_sig_len: *mut c_ulonglong,
        message: *const c_uchar,
        message_len: c_ulonglong,
        secret_key: *const c_uchar,
    ) -> c_int;

    fn crypto_sign_verify_detached(
        sign: *const c_uchar,
        message: *const c_uchar,
        message_len: c_ulonglong,
        publiy_key: *const c_uchar,
    ) -> c_int;

    fn sodium_pad(
        padded_buflen: *mut usize,
        buf: *mut c_uchar,
        unpadded_buflen: usize,
        block_size: usize,
        max_buflen: usize,
    ) -> c_int;

    fn sodium_unpad(
        unpadded_buflen: *mut usize,
        buf: *const c_uchar,
        padded_buflen: usize,
        block_size: usize,
    ) -> c_int;
}
