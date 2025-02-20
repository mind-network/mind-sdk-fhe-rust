# mind-sdk-fhe-rust
`mind_sdk_fhe` is a **Fully Homomorphic Encryption (FHE) Utility SDK** written in **Native Rust** by [Mind Network](https://www.mindnetwork.xyz/). 


[![mind_sdk_fhe on crates.io](https://img.shields.io/crates/v/mind_sdk_fhe)](https://crates.io/crates/mind_sdk_fhe)
[![Documentation on docs.rs](https://img.shields.io/badge/docs-docs.rs-blue)](https://docs.rs/mind_sdk_fhe)
[![Licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Github](https://img.shields.io/badge/source-github.com-blue.svg)](https://github.com/mind-network/mind-sdk-fhe-rust)
[![Github](https://img.shields.io/badge/build-pass-green.svg)](https://github.com/mind-network/mind-sdk-fhe-rust)

## Features
- 🚀 **Rust Native** – Safe memory management and high performance.
- 🔐 **Fully Homomorphic Encryption (FHE) Support** – Enables computation over encrypted data.
- 📌 **Multi-Type Support** – Operations over int, shortint, and general data types.

## Quick Start

### Install 
```toml
[dependencies]
mind_sdk_fhe = "*
```

### Run 
```bash
cargo run
```


### FHE General Example
```rust
pub fn test_new_in_memory() {
    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();

    ts.reset();
    let mut fhe_general = mind_sdk_fhe::FheGeneral::default();
    fhe_general.new_in_memory();
    tm.insert("fhe_general gen", ts.duration());

    let fhe = mind_sdk_fhe::FheInt::from(fhe_general);
    tm.insert("fhe_int gen", ts.duration());

    let x = 2;
    let x_ct: tfhe::integer::RadixCiphertext = fhe.encrypt_by_public_key::<u8>(x); 
    tm.insert("encrypt_by_public_key", ts.duration_and_reset());

    let z_ct = fhe
        .compute_key
        .as_ref()
        .unwrap()
        .checked_add(&x_ct, &x_ct)
        .unwrap();
    tm.insert("checked_add", ts.duration_and_reset());

    let z_pt: u8 = fhe.decrypt_by_private_key::<u8>(&z_ct); 
    tm.insert("decrypt", ts.duration_and_reset());

    println!(
        "pt: {:?}, ct: {:?}, match: {}, bin: {:#066b}",
        x + x,
        &z_pt,
        (x + x) == (z_pt),
        &z_pt
    );
    tm.pprint();
}
```

### FHE Integer Example
```rust
pub fn test_new_in_memory() {
    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();

    ts.reset();
    let mut fhe = mind_sdk_fhe::FheGeneral::default();
    fhe.new_in_memory();
    tm.insert("fhepk_load", ts.duration());

    let x = 2;
    let x_ct: tfhe::FheUint8 = fhe.encrypt_by_public_key::<u8, tfhe::FheUint8>(x); 
    tm.insert("encrypt_by_public_key", ts.duration_and_reset());

    tfhe::set_server_key(fhe.compute_key.clone().unwrap());
    tm.insert("set_server_key", ts.duration_and_reset());

    let z_ct = &x_ct + &x_ct;
    tm.insert("+", ts.duration_and_reset());

    let z_pt: u8 = fhe.decrypt_by_private_key::<tfhe::FheUint8, u8>(&z_ct); 
    tm.insert("decrypt", ts.duration_and_reset());

    println!(
        "pt: {:?}, ct: {:?}, match: {}, bin: {:#066b}",
        x + x,
        &z_pt,
        (x + x) == (z_pt),
        &z_pt
    );
    tm.pprint();
}
```

### FHE ShortInt Example
```rust
pub fn test_new_in_memory() {
    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();

    ts.reset();
    let mut fhe_general = mind_sdk_fhe::FheGeneral::default();
    fhe_general.new_in_memory();
    tm.insert("fhe_general gen", ts.duration());

    let fhe_int = mind_sdk_fhe::FheInt::from(fhe_general);
    tm.insert("fhe_int gen", ts.duration());

    let fhe = mind_sdk_fhe::FheShortint::from(fhe_int);
    tm.insert("fhe_int gen", ts.duration());

    let x = 1;
    let x_ct: tfhe::shortint::Ciphertext = fhe.encrypt_by_public_key(x); 
    tm.insert("encrypt_by_public_key", ts.duration_and_reset());

    let z_ct = fhe
        .compute_key
        .as_ref()
        .unwrap()
        .checked_add(&x_ct, &x_ct)
        .unwrap();
    tm.insert("checked_add", ts.duration_and_reset());

    let z_pt: u64 = fhe.decrypt_by_private_key(&z_ct); 
    tm.insert("decrypt", ts.duration_and_reset());

    println!(
        "pt: {:?}, ct: {:?}, match: {}, bin: {:#066b}",
        x + x,
        &z_pt,
        (x + x) == (z_pt),
        &z_pt
    );
    tm.pprint();
}
```

## **License**

This project is licensed under the **MIT License**.

## **Contact**

For questions or support, please contact [Mind Network Official Channels](https://mindnetwork.xyz/).
