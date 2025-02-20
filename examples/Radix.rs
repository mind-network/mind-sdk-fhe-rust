use function_name;
use tfhe::integer::IntegerCiphertext;

#[function_name::named]
pub fn encode_decode_radix() {
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

    let x_u8 = 1 / 1 as u8; // 65_535
    let x_ct_int_u8: tfhe::integer::RadixCiphertext = fhepk_int.encrypt_by_public_key::<u8>(x_u8); //////////
                                                                                                   //let radix = mind_sdk_fhe::encode_u64_to_radix(x_u8 as u64, 4, 16);
    let radix = fhesk_int
        .private_key
        .clone()
        .unwrap()
        .encrypt_radix(x_u8 as u64, 4);
    let trim_lsb = fheck_int.trim_radix_blocks_lsb(&x_ct_int_u8, 2);
    let pt_trim_lsb: u128 = fhesk_int.decrypt_by_private_key(&trim_lsb); //////////////
                                                                         //let radix_trim_lsb = mind_sdk_fhe::encode_u64_to_radix(pt_trim_lsb as u64, 4, 16);
    let radix_trim_lsb = fhesk_int
        .private_key
        .clone()
        .unwrap()
        .encrypt_radix(pt_trim_lsb as u64, 4);
    let trim_msb = fheck_int.trim_radix_blocks_msb(&x_ct_int_u8, 2);
    let pt_trim_msb: u128 = fhesk_int.decrypt_by_private_key(&trim_msb); //////////////
    let radix_trim_msb = fhesk_int
        .private_key
        .clone()
        .unwrap()
        .encrypt_radix(pt_trim_msb as u64, 4);
    //let radix_trim_msb = mind_sdk_fhe::encode_u64_to_radix(pt_trim_msb as u64, 4, 16);
    println!(
        "clear: {}, radix: {:?}, \t trim_lsb:{:?}=>{}, \t trim_msb:{:?}=>{}",
        x_u8, radix, radix_trim_lsb, pt_trim_lsb, radix_trim_msb, pt_trim_msb
    );
    let mut pt_trim_msb = 0 as u64;
    if x_ct_int_u8.blocks().len() > 4 {
        let trim_msb =
            fheck_int.trim_radix_blocks_msb(&x_ct_int_u8, x_ct_int_u8.blocks().len() - 4);
        pt_trim_msb = fhesk_int.decrypt_by_private_key(&trim_msb); //////////////
    }
    //let radix_trim_msb = mind_sdk_fhe::encode_u64_to_radix(pt_trim_msb as u64, 4, 16);
    let radix_trim_msb = fhesk_int
        .private_key
        .clone()
        .unwrap()
        .encrypt_radix(pt_trim_msb as u64, 4);
    println!(
        "blocksize: {}, {:?} => {}",
        x_ct_int_u8.blocks().len(),
        radix_trim_msb,
        pt_trim_msb
    );

    let x_u8 = 99 / 1 as u8; // 65_535
    let x_ct_int_u8: tfhe::integer::RadixCiphertext = fhepk_int.encrypt_by_public_key::<u8>(x_u8); //////////
                                                                                                   //let radix = mind_sdk_fhe::encode_u64_to_radix(x_u8 as u64, 4, 16);
    let radix = fhesk_int
        .private_key
        .clone()
        .unwrap()
        .encrypt_radix(x_u8 as u64, 4);
    let trim_lsb = fheck_int.trim_radix_blocks_lsb(&x_ct_int_u8, 2);
    let pt_trim_lsb: u128 = fhesk_int.decrypt_by_private_key(&trim_lsb); //////////////
                                                                         //let radix_trim_lsb = mind_sdk_fhe::encode_u64_to_radix(pt_trim_lsb as u64, 4, 16);
    let radix_trim_lsb = fhesk_int
        .private_key
        .clone()
        .unwrap()
        .encrypt_radix(pt_trim_lsb as u64, 4);
    let trim_msb = fheck_int.trim_radix_blocks_msb(&x_ct_int_u8, 2);
    let pt_trim_msb: u128 = fhesk_int.decrypt_by_private_key(&trim_msb); //////////////
                                                                         //let radix_trim_msb = mind_sdk_fhe::encode_u64_to_radix(pt_trim_msb as u64, 4, 16);
    let radix_trim_msb = fhesk_int
        .private_key
        .clone()
        .unwrap()
        .encrypt_radix(pt_trim_msb as u64, 4);
    println!(
        "clear: {}, radix: {:?}, \t trim_lsb:{:?}=>{}, \t trim_msb:{:?}=>{}",
        x_u8, radix, radix_trim_lsb, pt_trim_lsb, radix_trim_msb, pt_trim_msb
    );
    println!("blocksize: {}", x_ct_int_u8.blocks().len());

    let x_u8 = 254 / 1 as u8; // 65_535
    let x_ct_int_u8: tfhe::integer::RadixCiphertext = fhepk_int.encrypt_by_public_key::<u8>(x_u8); //////////
                                                                                                   //let radix = mind_sdk_fhe::encode_u64_to_radix(x_u8 as u64, 4, 16);
    let radix = fhesk_int
        .private_key
        .clone()
        .unwrap()
        .encrypt_radix(x_u8 as u64, 4);
    let trim_lsb = fheck_int.trim_radix_blocks_lsb(&x_ct_int_u8, 2);
    let pt_trim_lsb: u128 = fhesk_int.decrypt_by_private_key(&trim_lsb); //////////////
                                                                         //let radix_trim_lsb = mind_sdk_fhe::encode_u64_to_radix(pt_trim_lsb as u64, 4, 16);
    let radix_trim_lsb = fhesk_int
        .private_key
        .clone()
        .unwrap()
        .encrypt_radix(pt_trim_lsb as u64, 4);
    let trim_msb = fheck_int.trim_radix_blocks_msb(&x_ct_int_u8, 2);
    let pt_trim_msb: u128 = fhesk_int.decrypt_by_private_key(&trim_msb); //////////////
                                                                         //let radix_trim_msb = mind_sdk_fhe::encode_u64_to_radix(pt_trim_msb as u64, 4, 16);
    let radix_trim_msb = fhesk_int
        .private_key
        .clone()
        .unwrap()
        .encrypt_radix(pt_trim_msb as u64, 4);
    println!(
        "clear: {}, radix: {:?}, \t trim_lsb:{:?}=>{}, \t trim_msb:{:?}=>{}",
        x_u8, radix, radix_trim_lsb, pt_trim_lsb, radix_trim_msb, pt_trim_msb
    );
    println!("blocksize: {}", x_ct_int_u8.blocks().len());

    let x_u16 = 441 / 1 as u16; // 65_535
    let x_ct_int_u16: tfhe::integer::RadixCiphertext =
        fhepk_int.encrypt_by_public_key::<u16>(x_u16); //////////
                                                       //let radix = mind_sdk_fhe::encode_u64_to_radix(x_u16 as u64, 4, 16);
    let radix = fhesk_int
        .private_key
        .clone()
        .unwrap()
        .encrypt_radix(x_u16 as u64, 4);
    let trim_lsb = fheck_int.trim_radix_blocks_lsb(&x_ct_int_u16, 2);
    let pt_trim_lsb: u128 = fhesk_int.decrypt_by_private_key(&trim_lsb); //////////////
                                                                         //let radix_trim_lsb = mind_sdk_fhe::encode_u64_to_radix(pt_trim_lsb as u64, 4, 16);
    let radix_trim_lsb = fhesk_int
        .private_key
        .clone()
        .unwrap()
        .encrypt_radix(pt_trim_lsb as u64, 4);
    let trim_msb = fheck_int.trim_radix_blocks_msb(&x_ct_int_u16, 2);
    let pt_trim_msb: u128 = fhesk_int.decrypt_by_private_key(&trim_msb); //////////////
                                                                         //let radix_trim_msb = mind_sdk_fhe::encode_u64_to_radix(pt_trim_msb as u64, 4, 16);
    let radix_trim_msb = fhesk_int
        .private_key
        .clone()
        .unwrap()
        .encrypt_radix(pt_trim_msb as u64, 4);
    println!(
        "clear: {}, radix: {:?}, \t trim_lsb:{:?}=>{}, \t trim_msb:{:?}=>{}",
        x_u16, radix, radix_trim_lsb, pt_trim_lsb, radix_trim_msb, pt_trim_msb
    );
    let mut pt_trim_msb = 0 as u64;
    if x_ct_int_u16.blocks().len() > 4 {
        let trim_msb =
            fheck_int.trim_radix_blocks_msb(&x_ct_int_u16, x_ct_int_u16.blocks().len() - 4);
        pt_trim_msb = fhesk_int.decrypt_by_private_key(&trim_msb); //////////////
    }
    //let radix_trim_msb = mind_sdk_fhe::encode_u64_to_radix(pt_trim_msb as u64, 4, 16);
    let radix_trim_msb = fhesk_int
        .private_key
        .clone()
        .unwrap()
        .encrypt_radix(pt_trim_msb as u64, 4);
    println!(
        "blocksize: {}, {:?} => {}",
        x_ct_int_u16.blocks().len(),
        radix_trim_msb,
        pt_trim_msb
    );

    let x_u16 = 65533 / 1 as u16; // 65_535
    let x_ct_int_u16: tfhe::integer::RadixCiphertext =
        fhepk_int.encrypt_by_public_key::<u16>(x_u16); //////////
                                                       //let radix = mind_sdk_fhe::encode_u64_to_radix(x_u16 as u64, 4, 16);
    let radix = fhesk_int
        .private_key
        .clone()
        .unwrap()
        .encrypt_radix(x_u16 as u64, 4);
    let trim_lsb = fheck_int.trim_radix_blocks_lsb(&x_ct_int_u16, 2);
    let pt_trim_lsb: u128 = fhesk_int.decrypt_by_private_key(&trim_lsb); //////////////
                                                                         //let radix_trim_lsb = mind_sdk_fhe::encode_u64_to_radix(pt_trim_lsb as u64, 4, 16);
    let radix_trim_lsb = fhesk_int
        .private_key
        .clone()
        .unwrap()
        .encrypt_radix(pt_trim_lsb as u64, 4);
    let trim_msb = fheck_int.trim_radix_blocks_msb(&x_ct_int_u16, 2);
    let pt_trim_msb: u128 = fhesk_int.decrypt_by_private_key(&trim_msb); //////////////
                                                                         //let radix_trim_msb = mind_sdk_fhe::encode_u64_to_radix(pt_trim_msb as u64, 4, 16);
    let radix_trim_msb = fhesk_int
        .private_key
        .clone()
        .unwrap()
        .encrypt_radix(pt_trim_msb as u64, 4);
    println!(
        "clear: {}, radix: {:?}, \t trim_lsb:{:?}=>{}, \t trim_msb:{:?}=>{}",
        x_u16, radix, radix_trim_lsb, pt_trim_lsb, radix_trim_msb, pt_trim_msb
    );
    let mut pt_trim_msb = 0 as u64;
    if x_ct_int_u16.blocks().len() > 4 {
        let trim_msb =
            fheck_int.trim_radix_blocks_msb(&x_ct_int_u16, x_ct_int_u16.blocks().len() - 4);
        pt_trim_msb = fhesk_int.decrypt_by_private_key(&trim_msb); //////////////
    }
    //let radix_trim_msb = mind_sdk_fhe::encode_u64_to_radix(pt_trim_msb as u64, 4, 16);
    let radix_trim_msb = fhesk_int
        .private_key
        .clone()
        .unwrap()
        .encrypt_radix(pt_trim_msb as u64, 4);
    println!(
        "blocksize: {}, {:?} => {}",
        x_ct_int_u16.blocks().len(),
        radix_trim_msb,
        pt_trim_msb
    );

    let x_u32 = 4294967293 / 1 as u32; // 4_294_967_295
    let x_ct_int_u32: tfhe::integer::RadixCiphertext =
        fhepk_int.encrypt_by_public_key::<u32>(x_u32); //////////
                                                       //let radix = mind_sdk_fhe::encode_u64_to_radix(x_u32 as u64, 4, 16);
    let radix = fhesk_int
        .private_key
        .clone()
        .unwrap()
        .encrypt_radix(x_u32 as u64, 4);
    let trim_lsb = fheck_int.trim_radix_blocks_lsb(&x_ct_int_u32, 2);
    let pt_trim_lsb: u128 = fhesk_int.decrypt_by_private_key(&trim_lsb); //////////////
                                                                         //let radix_trim_lsb = mind_sdk_fhe::encode_u64_to_radix(pt_trim_lsb as u64, 4, 16);
    let radix_trim_lsb = fhesk_int
        .private_key
        .clone()
        .unwrap()
        .encrypt_radix(pt_trim_lsb as u64, 4);
    let trim_msb = fheck_int.trim_radix_blocks_msb(&x_ct_int_u32, 2);
    let pt_trim_msb: u128 = fhesk_int.decrypt_by_private_key(&trim_msb); //////////////
                                                                         //let radix_trim_msb = mind_sdk_fhe::encode_u64_to_radix(pt_trim_msb as u64, 4, 16);
    let radix_trim_msb = fhesk_int
        .private_key
        .clone()
        .unwrap()
        .encrypt_radix(pt_trim_msb as u64, 4);
    println!(
        "clear: {}, radix: {:?}, \t trim_lsb:{:?}=>{}, \t trim_msb:{:?}=>{}",
        x_u32, radix, radix_trim_lsb, pt_trim_lsb, radix_trim_msb, pt_trim_msb
    );
    let mut pt_trim_msb = 0 as u64;
    if x_ct_int_u16.blocks().len() > 4 {
        let trim_msb =
            fheck_int.trim_radix_blocks_msb(&x_ct_int_u16, x_ct_int_u16.blocks().len() - 4);
        pt_trim_msb = fhesk_int.decrypt_by_private_key(&trim_msb); //////////////
    }
    //let radix_trim_msb = mind_sdk_fhe::encode_u64_to_radix(pt_trim_msb as u64, 4, 16);
    let radix_trim_msb = fhesk_int
        .private_key
        .clone()
        .unwrap()
        .encrypt_radix(pt_trim_msb as u64, 4);
    println!(
        "blocksize: {}, {:?} => {}",
        x_ct_int_u16.blocks().len(),
        radix_trim_msb,
        pt_trim_msb
    );
}

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

    let x_ct_int = fheck_int
        .compute_key
        .as_ref()
        .unwrap()
        .unchecked_add(&x_ct_int_u32, &x_ct_int_u32);
    let z_pt: u64 = fhesk_int.decrypt_by_private_key(&x_ct_int); //////////////
    println!("u32+u32: \t{}", z_pt);
    let x_ct_int = fheck_int
        .compute_key
        .as_ref()
        .unwrap()
        .unchecked_add(&x_ct_int_u32, &x_ct_int_u16);
    let z_pt: u64 = fhesk_int.decrypt_by_private_key(&x_ct_int); //////////////
    println!("u32+u32: \t{}", z_pt);
    let x_ct_int = fheck_int
        .compute_key
        .as_ref()
        .unwrap()
        .unchecked_add(&x_ct_int_u16, &x_ct_int_u8);
    let z_pt: u64 = fhesk_int.decrypt_by_private_key(&x_ct_int); //////////////
    println!("u16+u8: \t{}", z_pt);
    tm.insert("decrypt int {}", ts.duration_and_reset());
    let x_ct_int = fheck_int
        .compute_key
        .as_ref()
        .unwrap()
        .unchecked_add(&x_ct_int_u32, &x_ct_int_u8);
    let z_pt: u64 = fhesk_int.decrypt_by_private_key(&x_ct_int); //////////////
    println!("u32+u8: \t{}", z_pt);
    tm.insert("decrypt int {}", ts.duration_and_reset());

    println!("all above add are wong, becasue of overflow, unless cast first");
    tm.pprint();
}

#[function_name::named]
pub fn test_u8_add_u16_add_u32() {
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

    let x_u8 = 254 / 2 as u8; // 65_535
    let x_ct_int_u8: tfhe::integer::RadixCiphertext = fhepk_int.encrypt_by_public_key::<u8>(x_u8); //////////
    tm.insert("encrypt_by_public_key_int_u8", ts.duration_and_reset());
    let z_pt: u64 = fhesk_int.decrypt_by_private_key(&x_ct_int_u8); //////////////
    println!("u8: \t{}", z_pt);

    let x_u16 = 65535 / 2 as u16; // 65_535
    let x_ct_int_u16: tfhe::integer::RadixCiphertext =
        fhepk_int.encrypt_by_public_key::<u16>(x_u16); //////////
    tm.insert("encrypt_by_public_key_int_u16", ts.duration_and_reset());
    let z_pt: u64 = fhesk_int.decrypt_by_private_key(&x_ct_int_u16); //////////////
    println!("u16: \t{}", z_pt);

    let x_u32 = 4294967295 / 2 as u32; // 4_294_967_295
    let x_ct_int_u32: tfhe::integer::RadixCiphertext =
        fhepk_int.encrypt_by_public_key::<u32>(x_u32); //////////
    tm.insert("encrypt_by_public_key_int_u32", ts.duration_and_reset());
    let z_pt: u64 = fhesk_int.decrypt_by_private_key(&x_ct_int_u32); //////////////
    println!("u_32: \t{}", z_pt);

    let x_ct_int = fheck_int
        .compute_key
        .as_ref()
        .unwrap()
        .unchecked_add(&x_ct_int_u32, &x_ct_int_u32);
    let z_pt: u64 = fhesk_int.decrypt_by_private_key(&x_ct_int); //////////////
    println!("u32+u32: \t{}", z_pt);
    let x_ct_int = fheck_int
        .compute_key
        .as_ref()
        .unwrap()
        .unchecked_add(&x_ct_int_u32, &x_ct_int_u16);
    let z_pt: u64 = fhesk_int.decrypt_by_private_key(&x_ct_int); //////////////
    println!("u32+u32: \t{}", z_pt);
    let x_ct_int = fheck_int
        .compute_key
        .as_ref()
        .unwrap()
        .unchecked_add(&x_ct_int_u16, &x_ct_int_u8);
    let z_pt: u64 = fhesk_int.decrypt_by_private_key(&x_ct_int); //////////////
    println!("u16+u8: \t{}", z_pt);
    tm.insert("decrypt int {}", ts.duration_and_reset());
    let x_ct_int = fheck_int
        .compute_key
        .as_ref()
        .unwrap()
        .unchecked_add(&x_ct_int_u32, &x_ct_int_u8);
    let z_pt: u64 = fhesk_int.decrypt_by_private_key(&x_ct_int); //////////////
    println!("u32+u8: \t{}", z_pt);
    tm.insert("decrypt int {}", ts.duration_and_reset());

    let x_ct_int = fheck_int
        .compute_key
        .as_ref()
        .unwrap()
        .unchecked_add(&x_ct_int_u32, &x_ct_int_u16);
    let x_ct_int = fheck_int
        .compute_key
        .as_ref()
        .unwrap()
        .unchecked_add(&x_ct_int, &x_ct_int_u8);
    let z_pt: u64 = fhesk_int.decrypt_by_private_key(&x_ct_int); //////////////
    let total = (x_u32 as u64) + (x_u16 as u64) + (x_u8 as u64);
    let matched = z_pt == (total as u64);
    println!(
        "decrypt: {} = {}+{}+{}, {} match to {}",
        total, x_u32, x_u16, x_u8, matched, z_pt
    );

    let x_ct_int = fheck_int
        .compute_key
        .as_ref()
        .unwrap()
        .unchecked_add(&x_ct_int_u8, &x_ct_int_u16);
    let x_ct_int = fheck_int
        .compute_key
        .as_ref()
        .unwrap()
        .unchecked_add(&x_ct_int, &x_ct_int_u32);
    let z_pt: u64 = fhesk_int.decrypt_by_private_key(&x_ct_int); ////////////// it means need to add in big sequence, big number takes first
    let total = (x_u32 as u64) + (x_u16 as u64) + (x_u8 as u64);
    let matched = z_pt == (total as u64);
    println!(
        "decrypt: {} = {}+{}+{}, {} match to {}",
        total, x_u8, x_u16, x_u32, matched, z_pt
    );

    let fp_u8 = &format!("{}/ct_int_u8.txt", fpath_cts);
    let _ = mind_sdk_fhe::io::write(&x_ct_int_u8, fp_u8);
    println!(
        "fpath: {}, fsize: {}",
        fp_u8,
        mind_sdk_fhe::util::get_file_size(fp_u8)
    );
    let fp_u16 = &format!("{}/ct_int_u16.txt", fpath_cts);
    let _ = mind_sdk_fhe::io::write(&x_ct_int_u16, fp_u16);
    println!(
        "fpath: {}, fsize: {}",
        fp_u16,
        mind_sdk_fhe::util::get_file_size(fp_u16)
    );
    let fp_u32 = &format!("{}/ct_int_u32.txt", fpath_cts);
    let _ = mind_sdk_fhe::io::write(&x_ct_int_u32, fp_u32);
    println!(
        "fpath: {}, fsize: {}",
        fp_u32,
        mind_sdk_fhe::util::get_file_size(fp_u32)
    );

    println!("after casting: u8->u32, u16->u32");
    ts.reset();
    let x_ct_int_u8 = fheck_int
        .compute_key
        .as_ref()
        .unwrap()
        .cast_to_unsigned(x_ct_int_u8.clone(), 16);
    let x_ct_int_u16 = fheck_int
        .compute_key
        .as_ref()
        .unwrap()
        .cast_to_unsigned(x_ct_int_u16.clone(), 16);
    let x_ct_int = fheck_int
        .compute_key
        .as_ref()
        .unwrap()
        .unchecked_add(&x_ct_int_u8, &x_ct_int_u16);
    let x_ct_int = fheck_int
        .compute_key
        .as_ref()
        .unwrap()
        .unchecked_add(&x_ct_int, &x_ct_int_u32);
    let z_pt: u64 = fhesk_int.decrypt_by_private_key(&x_ct_int); ////////////// it means need to add in big sequence, big number takes first
    let total = (x_u32 as u64) + (x_u16 as u64) + (x_u8 as u64);
    let matched = z_pt == (total as u64);
    println!(
        "decrypt: {} = {}+{}+{}, {} match to {}, time: {:?}",
        total,
        x_u8,
        x_u16,
        x_u32,
        matched,
        z_pt,
        ts.duration_and_reset()
    );

    tm.pprint();
}

#[function_name::named]
pub fn test_radix_safe_sun() {
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

    let x_u8 = 1 / 1 as u8; // 65_535
    let x_ct_int_u8: tfhe::integer::RadixCiphertext = fhepk_int.encrypt_by_public_key::<u8>(x_u8); //////////
    tm.insert("encrypt_by_public_key_int_u8", ts.duration_and_reset());
    let z_pt: u64 = fhesk_int.decrypt_by_private_key(&x_ct_int_u8); //////////////
    println!("u8: \t{}", z_pt);

    let mut cts: Vec<tfhe::integer::RadixCiphertext> = Vec::new();
    let count = 100;
    for i in 0..count {
        let x_ct_int_u8_u16_2: tfhe::integer::RadixCiphertext =
            fhepk_int.encrypt_by_public_key::<u16>(100 as u16);
        cts.push(x_ct_int_u8_u16_2.clone());
    }
    println!("{}", count);
    ts.reset();
    let ct = fheck_int
        .compute_key
        .as_ref()
        .unwrap()
        .unchecked_sum_ciphertexts_parallelized(&cts)
        .unwrap(); // 221 second
    println!("== {:?}", ts.duration_and_reset());
    let z_pt: u64 = fhesk_int.decrypt_by_private_key(&ct); //////////////
    println!("ct: {}", z_pt);

    println!("all above add are wong, becasue of overflow, unless cast first");
    tm.pprint();
}

#[function_name::named]
pub fn test_radix_safe_add_u16() {
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

    let x_u8 = 1 / 1 as u8; // 65_535
    let x_ct_int_u8: tfhe::integer::RadixCiphertext = fhepk_int.encrypt_by_public_key::<u8>(x_u8); //////////
    tm.insert("encrypt_by_public_key_int_u8", ts.duration_and_reset());
    let z_pt: u64 = fhesk_int.decrypt_by_private_key(&x_ct_int_u8); //////////////
    println!("u8: \t{}", z_pt);

    let mut cts: Vec<tfhe::integer::RadixCiphertext> = Vec::new();
    let count = 100;
    let mut x_ct_int_u8_u16: tfhe::integer::RadixCiphertext =
        fhepk_int.encrypt_by_public_key::<u32>(0); //////////
    for i in 0..count {
        let x_ct_int_u8_u16_2: tfhe::integer::RadixCiphertext =
            fhepk_int.encrypt_by_public_key::<u16>(101 as u16);
        cts.push(x_ct_int_u8_u16_2.clone());
        x_ct_int_u8_u16 = fheck_int
            .compute_key
            .as_ref()
            .unwrap()
            .unchecked_add(&x_ct_int_u8_u16.clone(), &x_ct_int_u8_u16_2.clone()); // incorrect
                                                                                  //x_ct_int_u8_u16 = fheck_int.compute_key.as_ref().unwrap().scalar_add_parallelized(&x_ct_int_u8_u16.clone(), 100);
        println!("{} {}", i, x_ct_int_u8_u16.blocks().len());
    }
    println!("{}", count);
    ts.reset();
    //let ct = fheck_int.compute_key.as_ref().unwrap().unchecked_sum_ciphertexts_parallelized(&cts).unwrap();
    println!("== {:?}", ts.duration_and_reset());
    let z_pt: u64 = fhesk_int.decrypt_by_private_key(&x_ct_int_u8_u16); //////////////
    println!("ct: {}", z_pt);

    /*
    let count = 150000;
    //let mut x_ct_int_u8_u16 = fheck_int.compute_key.as_ref().unwrap().cast_to_unsigned(x_ct_int_u8.clone(), 32);
    let mut x_ct_int_u8_u16: tfhe::integer::RadixCiphertext = fhepk_int.encrypt_by_public_key::<u32>(0); //////////
    let z_pt:u64 = fhesk_int.decrypt_by_private_key(&x_ct_int_u8_u16); //////////////
    println!("x_ct_int_u8_u16: \t{}", z_pt);
    for i in 0..count {
        let mut x_ct_int_u8_u16_2: tfhe::integer::RadixCiphertext = fhepk_int.encrypt_by_public_key::<u32>(i as u32); //////////
        //let x_ct_int_u8_u16_2 = fheck_int.compute_key.as_ref().unwrap().cast_to_unsigned(x_ct_int_u8.clone(), 32);
        x_ct_int_u8_u16 = fheck_int.compute_key.as_ref().unwrap().checked_add(&x_ct_int_u8_u16.clone(), &x_ct_int_u8_u16_2.clone()).unwrap().clone();
        //let x_ct_int_u8_u16_3 = fheck_int.compute_key.as_ref().unwrap().unchecked_add(&x_ct_int_u8_u16_2, &x_ct_int_u8_u16);
        //x_ct_int_u8_u16 = x_ct_int_u8_u16_3.clone();
        //fheck_int.compute_key.as_ref().unwrap().smart_add_assign(&mut x_ct_int_u8_u16, &mut x_ct_int_u8_u16_2);
        //x_ct_int_u8_u16 = fheck_int.compute_key.as_ref().unwrap().smart_add_parallelized(&mut x_ct_int_u8_u16, &mut x_ct_int_u8_u16_2);
        //fheck_int.compute_key.as_ref().unwrap().unchecked_add_assign_parallelized(&mut x_ct_int_u8_u16, &mut x_ct_int_u8_u16_2);
        let z_pt:u64 = fhesk_int.decrypt_by_private_key(&x_ct_int_u8_u16); //////////////
        let z_pt_2:u64 = fhesk_int.decrypt_by_private_key(&x_ct_int_u8_u16_2); //////////////
        println!("x_ct_int_u8_u16: \t{} = \t{} = \t{}", z_pt, z_pt_2, i);
    }
    let z_pt:u64 = fhesk_int.decrypt_by_private_key(&x_ct_int_u8_u16); //////////////
    let total = (x_u8 as u64) * count;
    let matched = z_pt == (total as u64);
    println!("decrypt: {} = {}*{}, {} match to {}, time: {:?}", total, x_u8, count, matched, z_pt, ts.duration_and_reset());
    */

    println!("all above add are wong, becasue of overflow, unless cast first");
    tm.pprint();
}

pub fn main() {
    encode_decode_radix();
    //test_radix_overflow();
    //test_u8_add_u16_add_u32();
    //test_radix_sum();
    //test_radix_safe_add_u16();
}
