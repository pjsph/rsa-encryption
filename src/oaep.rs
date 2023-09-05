use std::io::{Error, ErrorKind};

use rand::Rng;
use sha2::{Sha256, Digest, digest::FixedOutputReset};

use crate::mgf::mgf;

const H_LEN: usize = 32;
const K: usize = 512;
const L: &[u8; 0] = b"";

pub fn encode<R: Rng>(mut hasher: Sha256, message: &[u8], rng: &mut R) -> Result<Vec<u8>, Error> {
    hasher.update(L);
    let l_hash = hasher.finalize_fixed_reset();
    let ps: Vec<u8> = vec![0; K - message.len() - 2*H_LEN - 2];

    let mut db: Vec<u8> = Vec::with_capacity(K - H_LEN - 1);
    db.extend(l_hash);
    db.extend(ps);
    db.push(0x01);
    db.extend(message);

    let seed = &mut [0u8; H_LEN];
    rng.fill_bytes(seed);

    let masked_db = match mask_with(&db, seed) {
        Ok(masked_db) => masked_db,
        Err(e) => return Err(Error::new(ErrorKind::Other, e))
    };
    let masked_seed = match mask_with(seed, &masked_db) {
        Ok(masked_seed) => masked_seed,
        Err(e) => return Err(Error::new(ErrorKind::Other, e))
    };

    let mut encoded_message: Vec<u8> = Vec::with_capacity(K);
    encoded_message.push(0x00);
    encoded_message.extend(masked_seed);
    encoded_message.extend(masked_db);

    Ok(encoded_message)
}

pub fn decode(mut hasher: Sha256, message: Vec<u8>) -> Result<Vec<u8>, Error> {
    hasher.update(L);
    let l_hash = hasher.finalize_fixed_reset().to_vec();
    let masked_seed = &message[1..H_LEN+1];
    let masked_db = &message[H_LEN+1..];

    let seed = match mask_with(masked_seed, masked_db) {
        Ok(seed) => seed,
        Err(e) => return Err(Error::new(ErrorKind::Other, e))
    };
    let db = match mask_with(masked_db, &seed) {
        Ok(db) => db,
        Err(e) => return Err(Error::new(ErrorKind::Other, e))
    };

    let l_hash2 = &db[..H_LEN];
    if l_hash2 != l_hash {
        return Err(Error::new(ErrorKind::Other, "ERROR: hashes are not identical."));
    }

    let mut decoded_message: Vec<u8> = vec![];
    let mut separator: usize = 0;
    for i in H_LEN..K {
        if db[i] == 0x01 && separator == 0 {
            separator = i;
            break;
        }
        if db[i] != 0x00 {
            // PS
            return Err(Error::new(ErrorKind::Other, "ERROR: PS doesn't consist only of 0x00."));
        }
    }
    if separator == 0 {
        return Err(Error::new(ErrorKind::Other, "ERROR: no separator / message is empty."));
    }
    decoded_message.extend(&db[separator+1..]);

    Ok(decoded_message)
}

fn mask_with(message: &[u8], seed: &[u8]) -> Result<Vec<u8>, Error> {
    let mask = match mgf(Sha256::new(), seed, message.len()) {
        Ok(mask) => mask,
        Err(e) => {
            return Err(Error::new(ErrorKind::Other, e));
        }
    };

    let mut masked_message = vec![0u8; message.len()];

    for i in 0..message.len() {
        masked_message[i] = message[i] ^ mask[i];
    }

    Ok(masked_message)
}