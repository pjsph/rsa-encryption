use std::{io::Error, str::FromStr};

use num_bigint_dig::BigUint;

use crate::key::{PublicKey, PrivateKey};

pub fn encrypt(public_key: &PublicKey, message: &Vec<u8>) -> Result<BigUint, Error>{
    let message_data = BigUint::from_bytes_be(message);
    Ok(message_data.modpow(&public_key.e, &public_key.n))
}

pub fn decrypt(private_key: &PrivateKey, message: &String) -> Result<Vec<u8>, Error> {
    let encrypted_message_data = match BigUint::from_str(&message) {
        Ok(data) => data,
        Err(e) => return Err(Error::new(std::io::ErrorKind::Other, e))
    };
    let message_data = encrypted_message_data.modpow(&private_key.d, &private_key.pub_key.n);

    // fix because the 0x00 is lost
    let mut message_data_bytes: Vec<u8> = vec![0];
    message_data_bytes.extend(BigUint::to_bytes_be(&message_data));
    Ok(message_data_bytes)
}