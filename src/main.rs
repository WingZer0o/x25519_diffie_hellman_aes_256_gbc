use aes_gcm::{aead::Aead, aes::Aes128, AeadCore, Aes256Gcm, Key, KeyInit};
use x25519_dalek::{EphemeralSecret, PublicKey};
use rand_core::OsRng;

fn main() {
    let alice_secret = EphemeralSecret::new(OsRng);
    let alice_public = PublicKey::from(&alice_secret);
    let bob_secret = EphemeralSecret::new(OsRng);
    let bob_public = PublicKey::from(&bob_secret);
    let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);
    let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);
    
    let to_encrypt = b"12345123123";

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let bob_aes_key = Key::<Aes256Gcm>::from_slice(bob_shared_secret.as_bytes());
    let alice_aes_key = Key::<Aes256Gcm>::from_slice(alice_shared_secret.as_bytes());

    let bob_cipher = Aes256Gcm::new(&bob_aes_key);
    let alice_cipher = Aes256Gcm::new(&alice_aes_key);

    let ciphertext = bob_cipher.encrypt(&nonce, to_encrypt.as_ref()).unwrap();

    let plaint_text = alice_cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();
    let result = plaint_text.eq(&to_encrypt);
    println!("{}", result);
}
