use rand::{thread_rng, Rng};

use crypto::aes::KeySize;
use crypto::aes_gcm::AesGcm;
use crypto::aead::AeadEncryptor;
use crypto::aead::AeadDecryptor;

use std::iter::repeat;

use hex;

use crate::consts::{AES_IV_LENGTH, AES_IV_PLUS_TAG_LENGTH, AES_TAG_LENGTH, EMPTY_BYTES};

/// AES-256-GCM encryption wrapper
pub fn aes_encrypt(key: &[u8], msg: &[u8]) -> Option<Vec<u8>> {

    let mut iv = [0u8; AES_IV_LENGTH];
    thread_rng().fill(&mut iv);

    let mut cipher = AesGcm::new(KeySize::KeySize256, &key[..], &iv[..], &EMPTY_BYTES);
    let mut output = Vec::with_capacity(AES_IV_PLUS_TAG_LENGTH + msg.len());
    let mut tag = [0u8; AES_TAG_LENGTH];

    let mut out: Vec<u8> = repeat(0).take(msg.len()).collect();

    cipher.encrypt(&msg[..], &mut out[..], &mut tag[..]);

    println!("{:?}", hex::encode(&key));

    println!("{:?}", hex::encode(&msg));

    let mut iv = [0u8; AES_IV_LENGTH];
    thread_rng().fill(&mut iv);

    output.extend(&iv);

    println!("{:?}", hex::encode(&output));

    output.extend(&tag);

    println!("{:?}", hex::encode(&output));

    output.extend(&out);

    println!("{:?}", hex::encode(&output));

    if output.len() > 0 {
        Some(output)
    } else {
        None
    }
}

/// AES-256-GCM decryption wrapper
pub fn aes_decrypt(key: &[u8], encrypted_msg: &[u8]) -> Option<Vec<u8>> {
    if encrypted_msg.len() < AES_IV_PLUS_TAG_LENGTH {
        return None;
    }

    println!("{:?}", hex::encode(&encrypted_msg));

    let iv = &encrypted_msg[..AES_IV_LENGTH];

    println!("{:?}", hex::encode(&iv));

    let tag = &encrypted_msg[AES_IV_LENGTH..AES_IV_PLUS_TAG_LENGTH];

    println!("{:?}", hex::encode(&tag));

    let encrypted = &encrypted_msg[AES_IV_PLUS_TAG_LENGTH..];

    println!("{:?}", hex::encode(&encrypted));

    let mut decipher = AesGcm::new(KeySize::KeySize256, &key[..], &iv[..], &EMPTY_BYTES);
    let mut out: Vec<u8> = repeat(0).take(encrypted.len()).collect();
    let result = decipher.decrypt(&encrypted[..], &mut out[..], &tag[..]);

    println!("{:?}", hex::encode(&out));

    if result {
        Some(out)
    } else {
        None
    }
}
