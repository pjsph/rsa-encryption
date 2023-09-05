use std::{io::Error, str::FromStr};

use num_bigint_dig::BigUint;

use crate::key::{PublicKey, PrivateKey};

pub fn encrypt(public_key: &PublicKey, message: &String) -> Result<BigUint, Error>{
    let message_data = BigUint::from_bytes_be(message.as_bytes());
    Ok(message_data.modpow(&public_key.e, &public_key.n))
}

pub fn decrypt(private_key: &PrivateKey, message: &String) -> Result<String, Error> {
    let encrypted_message_data = match BigUint::from_str(&message) {
        Ok(data) => data,
        Err(e) => return Err(Error::new(std::io::ErrorKind::Other, e))
    };
    let message_data = encrypted_message_data.modpow(&private_key.d, &private_key.pub_key.n);
    match String::from_utf8(BigUint::to_bytes_be(&message_data)) {
        Ok(decrypted_message) => Ok(decrypted_message),
        Err(e) => Err(Error::new(std::io::ErrorKind::Other, e))
    }
}