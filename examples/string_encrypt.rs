use hcl::Hcl;

fn main() {
    let hcl = Hcl::new().unwrap();
    let key = hcl.gen_symmetric_key();

    let message = "hello";

    println!("Encrypting {message}");

    let encrypted = hcl
        .string_symmetric_encrypt(key, message)
        .expect("Failed to encrypt");

    println!(
        "Encrypted as base 64: {}",
        hcl.bin_to_base64(&*encrypted)
            .expect("Failed to convert to base64")
    );

    let decrypted = hcl
        .string_symmetric_decrypt(key, &*encrypted)
        .expect("Failed to decrypt");

    println!("Decrypted: {decrypted}");

    assert_ne!(message.as_bytes(), &*encrypted);
    assert_eq!(message, decrypted.as_str());
}
