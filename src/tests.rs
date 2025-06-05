use crate::Hcl;

#[test]
fn test_base64() {
    let hcl = Hcl::new().unwrap();
    let k = hcl.string_to_symmetric_key("hallo", "fisch").unwrap();
    let b64_encoded = hcl.bin_to_base64(&k).unwrap();
    let b64_decoded = hcl.base64_to_bin(&b64_encoded).unwrap();

    assert_ne!(&k, b64_encoded.as_bytes());
    assert_ne!(b64_decoded.as_ref(), b64_encoded.as_bytes());
    assert_eq!(32, b64_decoded.len());
    assert_eq!(k, *b64_decoded);
}

#[test]
fn test_without_nonce_key_encrypt_decrypt() {
    let hcl = Hcl::new().unwrap();
    let k = hcl.gen_symmetric_key();
    let msg = "hallo ich bin eine äääöö$§§ test nachricht ";
    let encrypted = hcl.string_symmetric_encrypt(k, msg).unwrap();
    let decrypted = hcl.string_symmetric_decrypt(k, &encrypted).unwrap();

    assert_ne!(encrypted.as_ref(), msg.as_bytes());
    assert_ne!(encrypted.as_ref(), decrypted.as_bytes());
    assert_eq!(msg, decrypted);
}

#[test]
fn test_signatures() {
    let hcl = Hcl::new().unwrap();
    let (pk, sk) = hcl.gen_sign_keypair();
    let (other_pk, _) = hcl.gen_sign_keypair();

    let msg = "cmd\npayÄ§load";

    let signed = hcl.sign_str(&msg, sk).unwrap();

    assert_ne!(signed.as_ref(), msg.as_bytes());
    assert_eq!(None, hcl.sign_open(&signed, other_pk));

    let opened_sign = hcl.sign_open(&signed, pk).unwrap();
    assert_eq!(msg.as_bytes(), opened_sign.as_ref());
}

#[test]
fn test_detached_signatures() {
    let hcl = Hcl::new().unwrap();
    let msg = "Hallo";

    let (pk, sk) = hcl.gen_sign_keypair();
    let (other_pk, _) = hcl.gen_sign_keypair();

    let sig = hcl.sign_str_detached(&msg, sk).unwrap();
    assert!(!sig.is_empty());
    assert!(hcl.sign_detached_verify(&msg, &sig, pk));
    assert!(!hcl.sign_detached_verify(&msg, &sig, other_pk));
}

#[test]
fn test_randombytes_buf() {
    let hcl = Hcl::new().unwrap();
    let mut buf = [0; 1024];
    let copied_buf = buf.clone();
    assert_eq!(buf, copied_buf);
    hcl.gen_random_bytes(&mut buf);
    assert_ne!(buf, copied_buf);
}

#[test]
fn test_padding_raw() {
    let msg = "Hallo ich bin ein Fisch!";
    let mut padded_buf = vec![0; msg.len() + 16];
    msg.as_bytes()
        .iter()
        .enumerate()
        .for_each(|(i, x)| padded_buf[i] = *x);
    assert_eq!(msg.as_bytes(), &padded_buf[..msg.len()]);
    let mut padded_len: usize = 0;
    unsafe {
        let res = crate::sodium_pad(
            &mut padded_len,
            padded_buf.as_mut_ptr(),
            msg.len(),
            16,
            padded_buf.len(),
        );

        assert_eq!(0, res);
    }
    let padded_buf = padded_buf[..padded_len].to_vec();
    assert_eq!(padded_len, padded_buf.len());
    let mut unpadded_len: usize = 0;

    unsafe {
        let res = crate::sodium_unpad(&mut unpadded_len, padded_buf.as_ptr(), padded_buf.len(), 16);
        assert_eq!(0, res);
    }

    let unpadded_buf = padded_buf[..unpadded_len].to_vec();
    assert_eq!(unpadded_len, msg.len());

    assert_eq!(Ok(msg.into()), String::from_utf8(unpadded_buf));

    assert_ne!(0, padded_len);
}

#[test]
fn test_double_ratchet() {
    let hcl = Hcl::new().unwrap();
    let root_key = hcl.gen_symmetric_key();
    let mut root_ratchet = hcl.new_ratchet(root_key);

    let (k1, _) = root_ratchet.advance().unwrap();
    let (k2, _) = root_ratchet.advance().unwrap();

    let (mut a_send, mut a_recv) = (hcl.new_ratchet(k1), hcl.new_ratchet(k2));
    let (mut b_send, mut b_recv) = (hcl.new_ratchet(k2), hcl.new_ratchet(k1));

    for msg in ["Hallo ÄÄ ich bin einßß??ß Fisc§§h!!  "] {
        assert_eq!(
            msg.to_string(),
            b_recv
                .decrypt_string(&a_send.encrypt_string(msg).unwrap())
                .unwrap()
        );
        assert_eq!(
            msg.to_string(),
            a_recv
                .decrypt_string(&b_send.encrypt_string(msg).unwrap())
                .unwrap()
        );
    }
}
