use std::{fs::File, io::{Write, Read}};

use clap::{Parser, Subcommand, Args};
use num_bigint_dig::BigUint;

use sha2::{Sha256, Digest};

mod key;
use key::PrivateKey;
use key::PublicKey;

mod rsa;
use rsa::{encrypt, decrypt};

mod mgf;

mod oaep;

#[derive(Parser)]
#[command(name = "encryption")]
#[command(author = "pjsph")]
struct Cli {
    #[command(subcommand)]
    command: Commands
}

#[derive(Subcommand, Clone)]
enum Commands {
    Generate,
    Encrypt(EncryptArgs),
    Decrypt(DecryptArgs)
}

#[derive(Args, Clone)]
struct EncryptArgs {
    message: String
}

#[derive(Args, Clone)]
struct DecryptArgs {
    message: String
}

fn main() {
    let cli = Cli::parse();

    let mut rng = rand::thread_rng();

    match &cli.command {
        Commands::Generate => {
            println!("Generating RSA keypair, please wait...");

            if let Ok(private_key) = PrivateKey::new(rng) {
                let public_key = private_key.pub_key;
                if let Ok(mut f) = File::create("key.pub") {
                    let mut data = public_key.n.to_bytes_be().to_vec();
                    data.extend(&public_key.e.to_bytes_be()); // e is stored on 3 bytes
                    if let Err(err) = f.write_all(&data) {
                        println!("ERROR: couldn't save the public key.");
                        println!("{}", err);
                    }
                } else {
                    println!("ERROR: couldn't save the public key.");
                }

                if let Ok(mut f) = File::create("key") {
                    if let Err(err) = f.write_all(&private_key.d.to_bytes_be()) {
                        println!("ERROR: couldn't save the private key.");
                        println!("{}", err);
                    }
                } else {
                    println!("ERROR: couldn't save the private key.");
                }

                println!("Keypair generated and stored in 'key.pub' and 'key' files.");
            }
        },
        Commands::Encrypt(args) => {
            println!("Encrypting your message with the public key...\n");

            if let Ok(mut f) = File::open("key.pub") {
                let mut data = vec![];
                if let Err(err) = f.read_to_end(&mut data) {
                    println!("ERROR: couldn't load the public key.");
                    println!("{}", err);
                } else {
                    let n = BigUint::from_bytes_be(&data[..512]);
                    let e = BigUint::from_bytes_be(&data[512..]);

                    let public_key = PublicKey {
                        n,
                        e
                    };

                    let encoded_message = match oaep::encode(Sha256::new(), &args.message.as_bytes(), &mut rng) {
                        Ok(res) => res,
                        Err(e) => {
                            println!("{}", e);
                            return ();
                        }
                    };

                    if let Ok(encrypted_message) = encrypt(&public_key, &encoded_message) {
                        println!("{}\n\nYour encrypted message can be found above.", encrypted_message);
                    } else {
                        println!("ERROR: couldn't encrypt your message.");
                    }
                }
            } else {
                println!("ERROR: couldn't load the public key.");
            }
        },
        Commands::Decrypt(args) => {
            println!("Decrypting your message with the private key...\n");

            if let Ok(mut f) = File::open("key") {
                let mut data = vec![];
                if let Err(err) = f.read_to_end(&mut data) {
                    println!("ERROR: couldn't load the private key.");
                    println!("{}", err);
                } else {
                    let d = BigUint::from_bytes_be(&data);

                    if let Ok(mut f) = File::open("key.pub") {
                        let mut data = vec![];
                        if let Err(err) = f.read_to_end(&mut data) {
                            println!("ERROR: couldn't load the public key.");
                            println!("{}", err);
                        } else {
                            let n = BigUint::from_bytes_be(&data[..512]);
                            let e = BigUint::from_bytes_be(&data[512..]);
        
                            let public_key = PublicKey {
                                n,
                                e
                            };
        
                            let private_key = PrivateKey {
                                pub_key: public_key,
                                d,
                                p: None,
                                q: None
                            };

                            if let Ok(decrypted_message) = decrypt(&private_key, &args.message) {
                                let decoded_message = match oaep::decode(Sha256::new(), decrypted_message) {
                                    Ok(decoded_message) => decoded_message,
                                    Err(e) => {
                                        println!("{}", e);
                                        return ()
                                    }
                                };

                                if let Ok(decoded_message_str) = String::from_utf8(decoded_message) {
                                    println!("{}\n\nYour decrypted message can be found above.", decoded_message_str);
                                } else {
                                    println!("ERROR: couldn't decode your message.");
                                }

                            } else {
                                println!("ERROR: couldn't decrypt your message.");
                            }
                        }
                    } else {
                        println!("ERROR: couldn't load the public key.");
                    }
                }
            } else {
                println!("ERROR: couldn't load the private key.");
            }
        }
    }
}
