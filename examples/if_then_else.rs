use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt32};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Basic configuration to use homomorphic integers
    let config = ConfigBuilder::default().build();

    // Key generation
    let (client_key, server_keys) = generate_keys(config);

    let clear_a = 32i32;
    let clear_b = -45i32;

    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();

    // Encrypting the input data using the (private) client_key
    // FheInt32: Encrypted equivalent to i32
    let encrypted_a = FheInt32::try_encrypt(clear_a, &client_key)?;
    let encrypted_b = FheInt32::try_encrypt(clear_b, &client_key)?;
    tm.insert("2 try_encrypt", ts.duration_and_reset());

    // On the server side:
    set_server_key(server_keys);
    tm.insert("set_server_key", ts.duration_and_reset());

    // Clear equivalent computations: 32 > -45
    let encrypted_comp = &encrypted_a.gt(&encrypted_b);
    tm.insert("encrypted_comp", ts.duration_and_reset());
    let clear_res = encrypted_comp.decrypt(&client_key);
    assert_eq!(clear_res, clear_a > clear_b);

    // `encrypted_comp` is a FheBool, thus it encrypts a boolean value.
    // This acts as a condition on which the
    // `select` function can be applied on.
    // Clear equivalent computations:
    // if 32 > -45 {result = 32} else {result = -45}
    let encrypted_res = &encrypted_comp.select(&encrypted_a, &encrypted_b);
    tm.insert("encrypted_comp.select", ts.duration_and_reset());

    let clear_res: i32 = encrypted_res.decrypt(&client_key);
    assert_eq!(clear_res, clear_a);
    tm.insert("decrypt: ", ts.duration_and_reset());

    tm.pprint();

    Ok(())
}
