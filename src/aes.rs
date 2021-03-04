use rand::{thread_rng, Rng};

use rust_crypto::aes::KeySize;
use rust_crypto::aes_gcm::AesGcm;

use crate::consts::{AES_IV_LENGTH, AES_IV_PLUS_TAG_LENGTH, AES_TAG_LENGTH, EMPTY_BYTES};

/// AES-256-GCM encryption wrapper
pub fn aes_encrypt(key: &[u8], msg: &[u8]) -> Option<Vec<u8>> {

    let mut iv = [0u8; AES_IV_LENGTH];
    thread_rng().fill(&mut iv);

    let mut cipher = AesGcm::new(KeySize::KeySize256, &key[..], &iv[..], &EMPTY_BYTES);
    let mut output = Vec::with_capacity(AES_IV_PLUS_TAG_LENGTH + msg.len());
    let mut tag = [0u8; AES_TAG_LENGTH];

    let mut out: Vec<u8> = repeat(0).take(item.plain_text.len()).collect();

    cipher.encrypt(&msg[..], &mut out[..], &mut tag[..]);

    let cipher = Cipher::aes_256_gcm();

    let mut iv = [0u8; AES_IV_LENGTH];
    thread_rng().fill(&mut iv);

    output.extend(&iv);
    output.extend(&tag);
    output.extend(out);

    if Ok(output) {
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

    let iv = &encrypted_msg[..AES_IV_LENGTH];
    let tag = &encrypted_msg[AES_IV_LENGTH..AES_IV_PLUS_TAG_LENGTH];
    let encrypted = &encrypted_msg[AES_IV_PLUS_TAG_LENGTH..];


    let mut decipher = AesGcm::new(KeySize::KeySize256, &key[..], &iv[..], &EMPTY_BYTES);
    let mut out: Vec<u8> = repeat(0).take(item.plain_text.len()).collect();
    let result = decipher.decrypt(&encrypted_msg[..], &mut out[..], &tag[..]);

    if result {
        Some(out)
    } else {
        None
    }
}
