use function_name;

#[function_name::named]
pub fn test_radix_overflow() {
    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";
    let (fpath_keys, fpath_cts, _fpath_pts) = mind_sdk_fhe::util::get_default_fpath();

    ts.reset();
    let fhepk_int =
        mind_sdk_fhe::FheInt::new_from_public_key_local(&format!("{}/fhepk.key", fpath));
    let fheck_int =
        mind_sdk_fhe::FheInt::new_from_compute_key_local(&format!("{}/fheck.key", fpath));
    ts.reset();
    let fhesk_int =
        mind_sdk_fhe::FheInt::new_from_private_key_local(&format!("{}/fhesk.key", fpath));
    tm.insert("load_fhe_int_keys", ts.duration_and_reset());
    println!(
        "sk message mod: {:?}, carry mod: {:?}",
        fheck_int.compute_key.as_ref().unwrap().message_modulus(),
        fheck_int.compute_key.as_ref().unwrap().carry_modulus()
    );
    println!(
        "pk size: {}, size_bytes: {}",
        &fhepk_int.public_key.as_ref().unwrap().size_elements(),
        &fhepk_int.public_key.as_ref().unwrap().size_bytes()
    );

    let x_u8 = 254 / 1 as u8; // 65_535
    let x_ct_int_u8: tfhe::integer::RadixCiphertext = fhepk_int.encrypt_by_public_key::<u8>(x_u8); //////////
    tm.insert("encrypt_by_public_key_int_u8", ts.duration_and_reset());
    let z_pt: u64 = fhesk_int.decrypt_by_private_key(&x_ct_int_u8); //////////////
    println!("u8: \t{}", z_pt);

    let x_u16 = 65535 / 1 as u16; // 65_535
    let x_ct_int_u16: tfhe::integer::RadixCiphertext =
        fhepk_int.encrypt_by_public_key::<u16>(x_u16); //////////
    tm.insert("encrypt_by_public_key_int_u16", ts.duration_and_reset());
    let z_pt: u64 = fhesk_int.decrypt_by_private_key(&x_ct_int_u16); //////////////
    println!("u16: \t{}", z_pt);

    let x_u32 = 4294967295 / 1 as u32; // 4_294_967_295
    let x_ct_int_u32: tfhe::integer::RadixCiphertext =
        fhepk_int.encrypt_by_public_key::<u32>(x_u32); //////////
    tm.insert("encrypt_by_public_key_int_u32", ts.duration_and_reset());
    let z_pt: u64 = fhesk_int.decrypt_by_private_key(&x_ct_int_u32); //////////////
    println!("u_32: \t{}", z_pt);

    let xx = ((std::u8::MAX as u128) - 10)..((std::u8::MAX as u128) + 10);
    for i in xx {
        let x = i as u8;
        println!(
            "type [{}] number [{}] needs [{}] blocks to represent: {:#0130b}",
            std::any::type_name_of_val(&x),
            x,
            fheck_int
                .compute_key
                .as_ref()
                .unwrap()
                .num_blocks_to_represent_unsigned_value(x),
            x
        );
    }
    println!("");

    let xx = ((std::u16::MAX as u128) - 10)..((std::u16::MAX as u128) + 10);
    for i in xx {
        let x = i as u16;
        println!(
            "type [{}] number [{}] needs [{}] blocks to represent: {:#0130b}",
            std::any::type_name_of_val(&x),
            x,
            fheck_int
                .compute_key
                .as_ref()
                .unwrap()
                .num_blocks_to_represent_unsigned_value(x),
            x
        );
    }
    println!("");

    let xx = ((std::u32::MAX as u128) - 10)..((std::u32::MAX as u128) + 10);
    for i in xx {
        let x = i as u32;
        println!(
            "type [{}] number [{}] needs [{}] blocks to represent: {:#0130b}",
            std::any::type_name_of_val(&x),
            x,
            fheck_int
                .compute_key
                .as_ref()
                .unwrap()
                .num_blocks_to_represent_unsigned_value(x),
            x
        );
    }
    println!("");

    let xx = ((std::u64::MAX as u128) - 10)..((std::u64::MAX as u128) + 10);
    for i in xx {
        let x = i as u64;
        println!(
            "type [{}] number [{}] needs [{}] blocks to represent: {:#0130b}",
            std::any::type_name_of_val(&x),
            x,
            fheck_int
                .compute_key
                .as_ref()
                .unwrap()
                .num_blocks_to_represent_unsigned_value(x),
            x
        );
    }
    println!("");

    let xx = ((std::u128::MAX as u128) - 10)..(std::u128::MAX as u128);
    for i in xx {
        let x = i as u128;
        println!(
            "type [{}] number [{}] needs [{}] blocks to represent: {:#0131b}_131",
            std::any::type_name_of_val(&x),
            x,
            fheck_int
                .compute_key
                .as_ref()
                .unwrap()
                .num_blocks_to_represent_unsigned_value(x),
            x
        );
    }
    println!("");

    /*
    let x_ct_int = fheck_int.compute_key.as_ref().unwrap().unchecked_add(&x_ct_int_u32, &x_ct_int_u32);
    let z_pt:u64 = fhesk_int.decrypt_by_private_key(&x_ct_int); //////////////
    println!("u32+u32: \t{}", z_pt);
    let x_ct_int = fheck_int.compute_key.as_ref().unwrap().unchecked_add(&x_ct_int_u32, &x_ct_int_u16);
    let z_pt:u64 = fhesk_int.decrypt_by_private_key(&x_ct_int); //////////////
    println!("u32+u32: \t{}", z_pt);
    let x_ct_int = fheck_int.compute_key.as_ref().unwrap().unchecked_add(&x_ct_int_u16, &x_ct_int_u8);
    let z_pt:u64 = fhesk_int.decrypt_by_private_key(&x_ct_int); //////////////
    println!("u16+u8: \t{}", z_pt);
    tm.insert("decrypt int {}", ts.duration_and_reset());
    let x_ct_int = fheck_int.compute_key.as_ref().unwrap().unchecked_add(&x_ct_int_u32, &x_ct_int_u8);
    let z_pt:u64 = fhesk_int.decrypt_by_private_key(&x_ct_int); //////////////
    println!("u32+u8: \t{}", z_pt);
    tm.insert("decrypt int {}", ts.duration_and_reset());
    */

    tm.pprint();
}

pub fn main() {
    test_radix_overflow();
}
