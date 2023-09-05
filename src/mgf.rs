use std::io::{Error, ErrorKind};

use sha2::{Sha256, Digest, digest::FixedOutputReset};

pub fn mgf(mut hasher: Sha256, seed: &[u8], length: usize) -> Result<Vec<u8>, Error> {
    if length > 32 << 32 {
        return Err(Error::new(ErrorKind::Other, "ERROR: mgf mask too long"));
    }

    let mut t: Vec<u8> = vec![];
    
    let mut counter = [0u8; 4];
    while t.len() < length {
        hasher.update(seed);
        hasher.update(&counter);
        let mut result = hasher.finalize_fixed_reset().to_vec();
        t.append(&mut result);
        inc_counter(&mut counter);
    }

    t.resize(length, 0);
    Ok(t)
}

fn inc_counter(counter: &mut [u8; 4]) {
    for i in (0..4).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            return;
        }
    }
}