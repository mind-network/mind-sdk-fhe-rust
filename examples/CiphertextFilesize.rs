use function_name;

#[function_name::named]
pub fn test_ciphertext_filesize() {
    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    ts.reset();
    let fhepk_general =
        mind_sdk_fhe::FheGeneral::new_from_public_key_local(&format!("{}/fhepk.key", fpath));
    tm.insert("fhepk_int", ts.duration_and_reset());

    ts.reset();
    let fhepk_int =
        mind_sdk_fhe::FheInt::new_from_public_key_local(&format!("{}/fhepk.key", fpath));
    tm.insert("fhepk_int", ts.duration_and_reset());

    ts.reset();
    let fhepk_shortint =
        mind_sdk_fhe::FheShortint::new_from_public_key_local(&format!("{}/fhepk.key", fpath));
    tm.insert("fhepk_int", ts.duration_and_reset());

    let x = 1;

    let x_ct_general: tfhe::FheUint8 = fhepk_general.encrypt_by_public_key::<u8, tfhe::FheUint8>(x); //////////
    tm.insert("encrypt_by_public_key_general", ts.duration_and_reset());

    let x_ct_int: tfhe::integer::RadixCiphertext = fhepk_int.encrypt_by_public_key::<u8>(x); //////////
    tm.insert("encrypt_by_public_key_int", ts.duration_and_reset());

    let x_ct_shortint: tfhe::shortint::Ciphertext = fhepk_shortint.encrypt_by_public_key(x as u64); //////////
    tm.insert("encrypt_by_public_key_shortint", ts.duration_and_reset());

    let fp_general = &format!("{}/ct_u8_general.txt", fpath);
    mind_sdk_fhe::io::write(&x_ct_general, fp_general).unwrap(); ///////////////
    tm.insert("ct_save_general", ts.duration_and_reset());
    let x_ct_general: tfhe::FheUint8 = mind_sdk_fhe::io::read(fp_general).unwrap(); ///////////
    tm.insert("ct_load_general", ts.duration_and_reset());

    let fp_int = &format!("{}/ct_u8_int.txt", fpath);
    mind_sdk_fhe::io::write(&x_ct_int, fp_int).unwrap(); ///////////////
    tm.insert("ct_save_int", ts.duration_and_reset());
    let x_ct_int: tfhe::integer::RadixCiphertext = mind_sdk_fhe::io::read(fp_int).unwrap(); ///////////
    tm.insert("ct_load_int", ts.duration_and_reset());

    let fp_shortint = &format!("{}/ct_u8_shortint.txt", fpath);
    mind_sdk_fhe::io::write(&x_ct_shortint, fp_shortint).unwrap(); ///////////////
    tm.insert("ct_save_shortint", ts.duration_and_reset());
    let x_ct_shortint: tfhe::shortint::Ciphertext = mind_sdk_fhe::io::read(fp_shortint).unwrap(); ///////////
    tm.insert("ct_load_shortint", ts.duration_and_reset());

    let fsize_general = &format!(
        " fpath: {}, fsize: {}",
        fp_general,
        mind_sdk_fhe::util::get_file_size(fp_general)
    );
    tm.insert(fsize_general, ts.duration_and_reset());
    let fsize_int = &format!(
        " fpath: {}, fsize: {}",
        fp_int,
        mind_sdk_fhe::util::get_file_size(fp_int)
    );
    tm.insert(fsize_int, ts.duration_and_reset());
    let fsize_shortint = &format!(
        " fpath: {}, fsize: {}",
        fp_shortint,
        mind_sdk_fhe::util::get_file_size(fp_shortint)
    );
    tm.insert(fsize_shortint, ts.duration_and_reset());

    let fheck_general =
        mind_sdk_fhe::FheGeneral::new_from_compute_key_local(&format!("{}/fheck.key", fpath));
    tfhe::set_server_key(fheck_general.compute_key.clone().unwrap());
    let z_ct_general = &x_ct_general + &x_ct_general;

    let fheck_int =
        mind_sdk_fhe::FheInt::new_from_compute_key_local(&format!("{}/fheck.key", fpath));
    let z_ct_int = fheck_int
        .compute_key
        .as_ref()
        .unwrap()
        .checked_add(&x_ct_int, &x_ct_int)
        .unwrap();

    let fheck_shortint =
        mind_sdk_fhe::FheShortint::new_from_compute_key_local(&format!("{}/fheck.key", fpath));
    let z_ct_shortint = fheck_shortint
        .compute_key
        .as_ref()
        .unwrap()
        .checked_add(&x_ct_shortint, &x_ct_shortint)
        .unwrap();

    let fhesk_general =
        mind_sdk_fhe::FheGeneral::new_from_private_key_local(&format!("{}/fhesk.key", fpath));
    let z_pt: u64 = fhesk_general.decrypt_by_private_key(&z_ct_general); //////////////
    tm.insert("decrypt int {}", ts.duration_and_reset());
    println!("decrypt: {} {}", x + x, z_pt);

    let fhesk_int =
        mind_sdk_fhe::FheInt::new_from_private_key_local(&format!("{}/fhesk.key", fpath));
    let z_pt: u64 = fhesk_int.decrypt_by_private_key(&z_ct_int); //////////////
    tm.insert("decrypt int {}", ts.duration_and_reset());
    println!("decrypt: {} {}", x + x, z_pt);

    let fhesk_shortint =
        mind_sdk_fhe::FheShortint::new_from_private_key_local(&format!("{}/fhesk.key", fpath));
    let z_pt: u64 = fhesk_shortint.decrypt_by_private_key(&z_ct_shortint); //////////////
    tm.insert("decrypt int {}", ts.duration_and_reset());
    println!("decrypt: {} {}", x + x, z_pt);

    tm.pprint();
}

pub fn main() {
    test_ciphertext_filesize();
}
