use function_name;

#[function_name::named]
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
    let x_ct: tfhe::integer::RadixCiphertext = fhe.encrypt_by_public_key::<u8>(x); //////////
    tm.insert("encrypt_by_public_key", ts.duration_and_reset());

    let z_ct = fhe
        .compute_key
        .as_ref()
        .unwrap()
        .checked_add(&x_ct, &x_ct)
        .unwrap();
    tm.insert("checked_add", ts.duration_and_reset());

    let z_pt: u8 = fhe.decrypt_by_private_key::<u8>(&z_ct); //////////////
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

#[function_name::named]
pub fn test_fhekeys_generation() {
    println!("\n== function: {} ==", function_name!());

    let fpath = "./data";
    let _ = mind_sdk_fhe::io::mkdir(fpath);

    let mut fhe = mind_sdk_fhe::FheInt::new();
    fhe.generate_keys_and_save_local_if_not_exist(fpath);

    let fp = &format!("{}/fhesk_int.key", fpath);
    println!(
        " fpath: {}, fsize: {}",
        fp,
        mind_sdk_fhe::util::get_file_size(fp)
    );
    let fp = &format!("{}/fheck_int.key", fpath);
    println!(
        " fpath: {}, fsize: {}",
        fp,
        mind_sdk_fhe::util::get_file_size(fp)
    );
    let fp = &format!("{}/fhepk_int.key", fpath);
    println!(
        " fpath: {}, fsize: {}",
        fp,
        mind_sdk_fhe::util::get_file_size(fp)
    );
}

#[function_name::named]
pub fn test_u8() {
    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    ts.reset();
    let fhepk =
        mind_sdk_fhe::FheInt::new_from_public_key_local(&format!("{}/fhepk_int.key", fpath));
    tm.insert("fhepk_load", ts.duration());

    let x = 2;
    let x_ct: tfhe::integer::RadixCiphertext = fhepk.encrypt_by_public_key::<u8>(x); //////////
    tm.insert("encrypt_by_public_key", ts.duration_and_reset());
    mind_sdk_fhe::io::write(&x_ct, &format!("{}/ct_u8_int.txt", fpath)).unwrap(); ///////////////
    tm.insert("ct_save", ts.duration_and_reset());

    let fp = &format!("{}/ct_u8_int.txt", fpath);
    let fsize = &format!(
        " fpath: {}, fsize: {}",
        fp,
        mind_sdk_fhe::util::get_file_size(fp)
    );
    tm.insert(fsize, ts.duration_and_reset());

    let x_ct: tfhe::integer::RadixCiphertext =
        mind_sdk_fhe::io::read(&format!("{}/ct_u8_int.txt", fpath)).unwrap(); ///////////
    tm.insert("ct_load", ts.duration_and_reset());

    let fheck =
        mind_sdk_fhe::FheInt::new_from_compute_key_local(&format!("{}/fheck_int.key", fpath));
    tm.insert("fheck_load", ts.duration_and_reset());

    let z_ct = fheck
        .compute_key
        .as_ref()
        .unwrap()
        .checked_add(&x_ct, &x_ct)
        .unwrap();
    tm.insert("checked_add", ts.duration_and_reset());

    let fhesk =
        mind_sdk_fhe::FheInt::new_from_private_key_local(&format!("{}/fhesk_int.key", fpath));
    tm.insert("fhesk_load", ts.duration_and_reset());

    let z_pt: u8 = fhesk.decrypt_by_private_key::<u8>(&z_ct); //////////////
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

#[function_name::named]
pub fn test_u16() {
    type T = u16;
    type U = tfhe::integer::RadixCiphertext;
    let t_typename = "u16";

    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    ts.reset();
    let fhepk =
        mind_sdk_fhe::FheInt::new_from_public_key_local(&format!("{}/fhepk_int.key", fpath));
    tm.insert("fhepk_load", ts.duration_and_reset());

    let x = 2 as T;
    let x_ct: U = fhepk.encrypt_by_public_key::<T>(x); //////////
    tm.insert("encrypt_by_public_key", ts.duration_and_reset());
    mind_sdk_fhe::io::write(&x_ct, &format!("{}/ct_{}_int.txt", fpath, t_typename)).unwrap(); ///////////////
    tm.insert("ct_save", ts.duration_and_reset());

    let fp = &format!("{}/ct_{}.txt", fpath, t_typename);
    let fsize = &format!(
        " fpath: {}, fsize: {}",
        fp,
        mind_sdk_fhe::util::get_file_size(fp)
    );
    tm.insert(fsize, ts.duration_and_reset());

    let x_ct: U = mind_sdk_fhe::io::read(&format!("{}/ct_{}_int.txt", fpath, t_typename)).unwrap(); ///////////
    tm.insert("ct_load", ts.duration_and_reset());

    let fheck =
        mind_sdk_fhe::FheInt::new_from_compute_key_local(&format!("{}/fheck_int.key", fpath));
    tm.insert("fheck_load", ts.duration_and_reset());

    let z_ct = fheck
        .compute_key
        .as_ref()
        .unwrap()
        .checked_add(&x_ct, &x_ct)
        .unwrap();
    tm.insert("checked_add", ts.duration_and_reset());

    let fhesk =
        mind_sdk_fhe::FheInt::new_from_private_key_local(&format!("{}/fhesk_int.key", fpath));
    tm.insert("fhesk_load", ts.duration_and_reset());

    let z_pt: T = fhesk.decrypt_by_private_key::<T>(&z_ct); //////////////
    tm.insert("decrypt", ts.duration_and_reset());

    let matched: bool = (x + x) == (z_pt);
    println!(
        "pt: {:?}, ct: {:?}, match: {:?}, bin: {:#066b}",
        x + x,
        &z_pt,
        matched,
        &z_pt
    );
    tm.pprint();
}

#[function_name::named]
pub fn test_u16_sum() {
    type T = u16;
    type U = tfhe::integer::RadixCiphertext;
    let t_typename = "u16";

    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    ts.reset();
    let fhepk =
        mind_sdk_fhe::FheInt::new_from_public_key_local(&format!("{}/fhepk_int.key", fpath));
    tm.insert("fhepk_load", ts.duration_and_reset());

    let x = 1 as T;
    let x_ct: U = fhepk.encrypt_by_public_key::<T>(x); //////////
    tm.insert("encrypt_by_public_key", ts.duration_and_reset());
    mind_sdk_fhe::io::write(&x_ct, &format!("{}/ct_{}_int.txt", fpath, t_typename)).unwrap(); ///////////////
    tm.insert("ct_save", ts.duration_and_reset());

    let fp = &format!("{}/ct_{}.txt", fpath, t_typename);
    let fsize = &format!(
        " fpath: {}, fsize: {}",
        fp,
        mind_sdk_fhe::util::get_file_size(fp)
    );
    tm.insert(fsize, ts.duration_and_reset());

    let x_ct: U = mind_sdk_fhe::io::read(&format!("{}/ct_{}_int.txt", fpath, t_typename)).unwrap(); ///////////
    tm.insert("ct_load", ts.duration_and_reset());

    let fheck =
        mind_sdk_fhe::FheInt::new_from_compute_key_local(&format!("{}/fheck_int.key", fpath));
    tm.insert("fheck_load", ts.duration_and_reset());

    let mut cts: Vec<U> = Vec::new();
    for _i in 0..100 {
        cts.push(x_ct.clone());
    }
    let mut z_ct = fheck
        .compute_key
        .as_ref()
        .unwrap()
        .smart_sum_ciphertexts_parallelized(cts)
        .unwrap();
    //z_ct = fheck.compute_key.as_ref().unwrap().unchecked_add(&z_ct, &x_ct);
    tm.insert(
        "smart_sum_ciphertexts_parallelized",
        ts.duration_and_reset(),
    );

    let fhesk =
        mind_sdk_fhe::FheInt::new_from_private_key_local(&format!("{}/fhesk_int.key", fpath));
    tm.insert("fhesk_load", ts.duration_and_reset());

    let z_pt: T = fhesk.decrypt_by_private_key::<T>(&z_ct); //////////////
    tm.insert("decrypt", ts.duration_and_reset());

    let matched: bool = (x + x) == (z_pt);
    println!(
        "pt: {:?}, ct: {:?}, match: {:?}, bin: {:#066b}",
        x + x,
        &z_pt,
        matched,
        &z_pt
    );
    tm.pprint();
}

#[function_name::named]
pub fn test_u16_loop() {
    type T = u16;
    type U = tfhe::integer::RadixCiphertext;
    let t_typename = "u16";

    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    ts.reset();
    let fhepk =
        mind_sdk_fhe::FheInt::new_from_public_key_local(&format!("{}/fhepk_int.key", fpath));
    tm.insert("fhepk_load", ts.duration_and_reset());

    let x = 1 as T;
    let x_ct: U = fhepk.encrypt_by_public_key::<T>(x); //////////
    tm.insert("encrypt_by_public_key", ts.duration_and_reset());
    mind_sdk_fhe::io::write(&x_ct, &format!("{}/ct_{}_int.txt", fpath, t_typename)).unwrap(); ///////////////
    tm.insert("ct_save", ts.duration_and_reset());

    let fp = &format!("{}/ct_{}.txt", fpath, t_typename);
    let fsize = &format!(
        " fpath: {}, fsize: {}",
        fp,
        mind_sdk_fhe::util::get_file_size(fp)
    );
    tm.insert(fsize, ts.duration_and_reset());

    let mut x_ct: U =
        mind_sdk_fhe::io::read(&format!("{}/ct_{}_int.txt", fpath, t_typename)).unwrap(); ///////////
    tm.insert("ct_load", ts.duration_and_reset());

    let fheck =
        mind_sdk_fhe::FheInt::new_from_compute_key_local(&format!("{}/fheck_int.key", fpath));
    tm.insert("fheck_load", ts.duration_and_reset());

    let mut z_ct = fhepk.encrypt_by_public_key::<T>(0);
    for _i in 0..10 {
        z_ct = fheck
            .compute_key
            .as_ref()
            .unwrap()
            .smart_add(&mut z_ct, &mut x_ct);
    }
    //let mut z_ct = fheck.compute_key.as_ref().unwrap().smart_sum_ciphertexts_parallelized(cts).unwrap();
    //z_ct = fheck.compute_key.as_ref().unwrap().unchecked_add(&z_ct, &x_ct);
    tm.insert(
        "smart_sum_ciphertexts_parallelized",
        ts.duration_and_reset(),
    );

    let fhesk =
        mind_sdk_fhe::FheInt::new_from_private_key_local(&format!("{}/fhesk_int.key", fpath));
    tm.insert("fhesk_load", ts.duration_and_reset());

    let z_pt: T = fhesk.decrypt_by_private_key::<T>(&z_ct); //////////////
    tm.insert("decrypt", ts.duration_and_reset());

    let matched: bool = (x + x) == (z_pt);
    println!(
        "pt: {:?}, ct: {:?}, match: {:?}, bin: {:#066b}",
        x + x,
        &z_pt,
        matched,
        &z_pt
    );
    tm.pprint();
}

#[function_name::named]
pub fn test_u128() {
    type T = u128;
    type U = tfhe::integer::RadixCiphertext;
    let t_typename = "u128";

    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    ts.reset();
    let fhepk =
        mind_sdk_fhe::FheInt::new_from_public_key_local(&format!("{}/fhepk_int.key", fpath));
    tm.insert("fhepk_load", ts.duration_and_reset());

    let x = 10000000 as T;
    let x_ct: U = fhepk.encrypt_by_public_key::<T>(x); //////////
    tm.insert("encrypt_by_public_key", ts.duration_and_reset());
    mind_sdk_fhe::io::write(&x_ct, &format!("{}/ct_{}_int.txt", fpath, t_typename)).unwrap(); ///////////////
    tm.insert("ct_save", ts.duration_and_reset());

    let fp = &format!("{}/ct_{}_int.txt", fpath, t_typename);
    let fsize = &format!(
        " fpath: {}, fsize: {}",
        fp,
        mind_sdk_fhe::util::get_file_size(fp)
    );
    tm.insert(fsize, ts.duration_and_reset());

    let x_ct: U = mind_sdk_fhe::io::read(&format!("{}/ct_{}_int.txt", fpath, t_typename)).unwrap(); ///////////
    tm.insert("ct_load", ts.duration_and_reset());

    let fheck =
        mind_sdk_fhe::FheInt::new_from_compute_key_local(&format!("{}/fheck_int.key", fpath));
    tm.insert("fheck_load", ts.duration_and_reset());

    let z_ct = fheck
        .compute_key
        .as_ref()
        .unwrap()
        .checked_add(&x_ct, &x_ct)
        .unwrap();
    tm.insert("checked_add", ts.duration_and_reset());

    let fhesk =
        mind_sdk_fhe::FheInt::new_from_private_key_local(&format!("{}/fhesk_int.key", fpath));
    tm.insert("fhesk_load", ts.duration_and_reset());

    let z_pt: T = fhesk.decrypt_by_private_key::<T>(&z_ct); //////////////
    tm.insert("decrypt", ts.duration_and_reset());

    let matched: bool = (x + x) == (z_pt);
    println!(
        "pt: {:?}, ct: {:?}, match: {:?}, bin: {:#066b}",
        x + x,
        &z_pt,
        matched,
        &z_pt
    );
    tm.pprint();
}

#[function_name::named]
pub fn test_u128_loop() {
    type T = u128;
    type U = tfhe::integer::RadixCiphertext;
    let t_typename = "u128";

    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    ts.reset();
    let fhepk =
        mind_sdk_fhe::FheInt::new_from_public_key_local(&format!("{}/fhepk_int.key", fpath));
    tm.insert("fhepk_load", ts.duration_and_reset());

    let x = 1 as T;
    let x_ct: U = fhepk.encrypt_by_public_key::<T>(x); //////////
    tm.insert("encrypt_by_public_key", ts.duration_and_reset());
    mind_sdk_fhe::io::write(&x_ct, &format!("{}/ct_{}_int.txt", fpath, t_typename)).unwrap(); ///////////////
    tm.insert("ct_save", ts.duration_and_reset());

    let fp = &format!("{}/ct_{}_int.txt", fpath, t_typename);
    let fsize = &format!(
        " fpath: {}, fsize: {}",
        fp,
        mind_sdk_fhe::util::get_file_size(fp)
    );
    tm.insert(fsize, ts.duration_and_reset());

    let x_ct: U = mind_sdk_fhe::io::read(&format!("{}/ct_{}_int.txt", fpath, t_typename)).unwrap(); ///////////
    tm.insert("ct_load", ts.duration_and_reset());

    let fheck =
        mind_sdk_fhe::FheInt::new_from_compute_key_local(&format!("{}/fheck_int.key", fpath));
    tm.insert("fheck_load", ts.duration_and_reset());

    let fhesk =
        mind_sdk_fhe::FheInt::new_from_private_key_local(&format!("{}/fhesk_int.key", fpath));
    tm.insert("fhesk_load", ts.duration_and_reset());

    let mut z_ct = fheck
        .compute_key
        .as_ref()
        .unwrap()
        .checked_add(&x_ct, &x_ct)
        .unwrap();
    z_ct = fheck
        .compute_key
        .as_ref()
        .unwrap()
        .unchecked_add(&z_ct, &x_ct);
    tm.insert("unchecked_add", ts.duration_and_reset());
    for _i in 0..10000 {
        z_ct = fheck
            .compute_key
            .as_ref()
            .unwrap()
            .unchecked_add(&z_ct, &x_ct);
        let z_pt: T = fhesk.decrypt_by_private_key::<T>(&z_ct); //////////////
                                                                //println!("i: {:#?}, ct: {:#?}", _i, z_pt);
    }
    tm.insert("unchecked_add_loop", ts.duration_and_reset());

    let z_pt: T = fhesk.decrypt_by_private_key::<T>(&z_ct); //////////////
    tm.insert("decrypt", ts.duration_and_reset());

    let matched: bool = (x + x) == (z_pt);
    println!(
        "pt: {:?}, ct: {:?}, match: {:?}, bin: {:#066b}",
        x + x,
        &z_pt,
        matched,
        &z_pt
    );
    tm.pprint();
}

#[function_name::named]
pub fn test_u128_sum() {
    type T = u128;
    type U = tfhe::integer::RadixCiphertext;
    let t_typename = "u128";

    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    ts.reset();
    let fhepk =
        mind_sdk_fhe::FheInt::new_from_public_key_local(&format!("{}/fhepk_int.key", fpath));
    tm.insert("fhepk_load", ts.duration_and_reset());

    let x = 1 as T;
    let x_ct: U = fhepk.encrypt_by_public_key::<T>(x); //////////
    tm.insert("encrypt_by_public_key", ts.duration_and_reset());
    mind_sdk_fhe::io::write(&x_ct, &format!("{}/ct_{}_int.txt", fpath, t_typename)).unwrap(); ///////////////
    tm.insert("ct_save", ts.duration_and_reset());

    let fp = &format!("{}/ct_{}_int.txt", fpath, t_typename);
    let fsize = &format!(
        " fpath: {}, fsize: {}",
        fp,
        mind_sdk_fhe::util::get_file_size(fp)
    );
    tm.insert(fsize, ts.duration_and_reset());

    let x_ct: U = mind_sdk_fhe::io::read(&format!("{}/ct_{}_int.txt", fpath, t_typename)).unwrap(); ///////////
    tm.insert("ct_load", ts.duration_and_reset());

    let fheck =
        mind_sdk_fhe::FheInt::new_from_compute_key_local(&format!("{}/fheck_int.key", fpath));
    tm.insert("fheck_load", ts.duration_and_reset());

    let fhesk =
        mind_sdk_fhe::FheInt::new_from_private_key_local(&format!("{}/fhesk_int.key", fpath));
    tm.insert("fhesk_load", ts.duration_and_reset());

    let mut cts: Vec<U> = Vec::new();
    for _i in 0..10 {
        cts.push(x_ct.clone());
    }
    let mut z_ct = fheck
        .compute_key
        .as_ref()
        .unwrap()
        .smart_sum_ciphertexts_parallelized(cts)
        .unwrap();
    z_ct = fheck
        .compute_key
        .as_ref()
        .unwrap()
        .unchecked_add(&z_ct, &x_ct);
    tm.insert(
        "smart_sum_ciphertexts_parallelized",
        ts.duration_and_reset(),
    );

    let z_pt: T = fhesk.decrypt_by_private_key::<T>(&z_ct); //////////////
    tm.insert("decrypt", ts.duration_and_reset());

    let matched: bool = (x + x) == (z_pt);
    println!(
        "pt: {:?}, ct: {:?}, match: {:?}, bin: {:#066b}",
        x + x,
        &z_pt,
        matched,
        &z_pt
    );
    tm.pprint();
}

#[function_name::named]
pub fn u128_if_then_else() {
    type T = u128;
    type U = tfhe::integer::RadixCiphertext;
    let t_typename = "u128";

    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    ts.reset();
    let fhepk =
        mind_sdk_fhe::FheInt::new_from_public_key_local(&format!("{}/fhepk_int.key", fpath));
    tm.insert("fhepk_load", ts.duration_and_reset());

    let x = 10 as T;
    let mut x_ct: U = fhepk.encrypt_by_public_key::<T>(x); //////////
    tm.insert("encrypt_by_public_key", ts.duration_and_reset());
    mind_sdk_fhe::io::write(&x_ct, &format!("{}/ct_{}_int.txt", fpath, t_typename)).unwrap(); ///////////////
    tm.insert("ct_save", ts.duration_and_reset());

    let y = 20 as T;
    let mut y_ct: U = fhepk.encrypt_by_public_key::<T>(y); //////////
    tm.insert("encrypt_by_public_key", ts.duration_and_reset());
    mind_sdk_fhe::io::write(&x_ct, &format!("{}/ct_{}_int.txt", fpath, t_typename)).unwrap(); ///////////////
    tm.insert("ct_save", ts.duration_and_reset());

    let fp = &format!("{}/ct_{}_int.txt", fpath, t_typename);
    let fsize = &format!(
        " fpath: {}, fsize: {}",
        fp,
        mind_sdk_fhe::util::get_file_size(fp)
    );
    tm.insert(fsize, ts.duration_and_reset());

    let mut x_ct: U =
        mind_sdk_fhe::io::read(&format!("{}/ct_{}_int.txt", fpath, t_typename)).unwrap(); ///////////
    tm.insert("ct_load", ts.duration_and_reset());

    let fheck =
        mind_sdk_fhe::FheInt::new_from_compute_key_local(&format!("{}/fheck_int.key", fpath));
    tm.insert("fheck_load", ts.duration_and_reset());

    let fhesk =
        mind_sdk_fhe::FheInt::new_from_private_key_local(&format!("{}/fhesk_int.key", fpath));
    tm.insert("fhesk_load", ts.duration_and_reset());

    let mut condition = fheck
        .compute_key
        .as_ref()
        .unwrap()
        .unchecked_ge(&x_ct, &y_ct);
    let ct_res = fheck
        .compute_key
        .as_ref()
        .unwrap()
        .unchecked_if_then_else_parallelized(&mut condition, &mut x_ct, &mut y_ct);
    let dec: T = fhesk.decrypt_by_private_key::<T>(&ct_res);
    println!("decrypt: {:#?}", dec);
    tm.insert(
        "unchecked_if_then_else_parallelized",
        ts.duration_and_reset(),
    );

    let z_ct = &x_ct;
    tm.insert("z_ct", ts.duration_and_reset());

    let z_pt: T = fhesk.decrypt_by_private_key::<T>(&z_ct); //////////////
    tm.insert("decrypt", ts.duration_and_reset());

    let matched: bool = (x + x) == (z_pt);
    println!(
        "pt: {:?}, ct: {:?}, match: {:?}, bin: {:#066b}",
        x + x,
        &z_pt,
        matched,
        &z_pt
    );
    tm.pprint();
}

pub fn main() {
    //test_new_in_memory();
    //test_fhekeys_generation();
    //test_u8();
    test_u16();
    test_u16_sum();
    test_u16_loop();
    //test_u128();
    //test_u128_loop();
    //test_u128_sum();
    //u128_if_then_else();
}
