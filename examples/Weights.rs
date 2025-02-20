use function_name;

#[function_name::named]
pub fn test_fhekeys_generation() {
    println!("\n== function: {} ==", function_name!());

    let fpath = "./data";
    let _ = mind_sdk_fhe::io::mkdir(fpath);

    let mut fhe = mind_sdk_fhe::FheShortint::new();
    fhe.generate_keys_and_save_local_if_not_exist(fpath);

    let fp = &format!("{}/fhesk_shortint.key", fpath);
    println!(
        " fpath: {}, fsize: {}",
        fp,
        mind_sdk_fhe::util::get_file_size(fp)
    );
    let fp = &format!("{}/fheck_shortint.key", fpath);
    println!(
        " fpath: {}, fsize: {}",
        fp,
        mind_sdk_fhe::util::get_file_size(fp)
    );
    let fp = &format!("{}/fhepk_shortint.key", fpath);
    println!(
        " fpath: {}, fsize: {}",
        fp,
        mind_sdk_fhe::util::get_file_size(fp)
    );

    // normal pk is 2.6gb which is too large for online transfer to user client, so have to use compactpk
    /* let fhesk = mind_sdk_fhe::FheShortint::new_from_private_key_local(&format!("{}/fhesk_shortint.key", fpath));
    let fhepk_shortint_normal = tfhe::shortint::PublicKey::new(&fhesk.private_key.unwrap());
    let _ = mind_sdk_fhe::io::write(
        fhepk_shortint_normal,
        &format!("{}/fhepk_shortint_normal_no_use.key", fpath),
    );
    let fp = &format!("{}/fhepk_shortint_normal_no_use.key", fpath);
    println!(" fpath: {}, fsize: {}", fp, mind_sdk_fhe::util::get_file_size(fp)); */
}

#[function_name::named]
pub fn test_u8_checked_add() {
    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    ts.reset();
    let fhepk = mind_sdk_fhe::FheShortint::new_from_public_key_local(&format!(
        "{}/fhepk_shortint.key",
        fpath
    ));
    tm.insert("fhepk_load", ts.duration());

    // encrypt
    let x = 1;
    let x_ct: tfhe::shortint::Ciphertext = fhepk.encrypt_by_public_key(x); //////////
    tm.insert("encrypt_by_public_key", ts.duration_and_reset());
    mind_sdk_fhe::io::write(&x_ct, &format!("{}/ct_u8_shortint.txt", fpath)).unwrap(); ///////////////
    tm.insert("ct_save", ts.duration_and_reset());

    // check encrypted filesize
    let fp = &format!("{}/ct_u8_shortint.txt", fpath);
    let fsize = &format!(
        " fpath: {}, fsize: {}",
        fp,
        mind_sdk_fhe::util::get_file_size(fp)
    );
    tm.insert(fsize, ts.duration_and_reset());

    let x_ct: tfhe::shortint::Ciphertext =
        mind_sdk_fhe::io::read(&format!("{}/ct_u8_shortint.txt", fpath)).unwrap(); ///////////
    tm.insert("ct_load", ts.duration_and_reset());

    // local ck to do compute
    let fheck = mind_sdk_fhe::FheShortint::new_from_compute_key_local(&format!(
        "{}/fheck_shortint.key",
        fpath
    ));
    tm.insert("fheck_load", ts.duration_and_reset());

    let z_ct = fheck
        .compute_key
        .as_ref()
        .unwrap()
        .checked_add(&x_ct, &x_ct)
        .unwrap();
    tm.insert("checked_add", ts.duration_and_reset());

    // local sk to decrpt
    let fhesk = mind_sdk_fhe::FheShortint::new_from_private_key_local(&format!(
        "{}/fhesk_shortint.key",
        fpath
    ));
    tm.insert("fhesk_load", ts.duration_and_reset());

    let z_pt: u64 = fhesk.decrypt_by_private_key(&z_ct); //////////////
    tm.insert("decrypt", ts.duration_and_reset());

    println!(
        "pt: {:?}, ct: {:?}, match: {}, bin: {:#066b}",
        x + x,
        &z_pt,
        (x + x) == (z_pt % 4),
        &z_pt
    );
    tm.pprint();
}

#[function_name::named]
pub fn test_u8_unchecked_add() {
    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    ts.reset();
    let fhepk = mind_sdk_fhe::FheShortint::new_from_public_key_local(&format!(
        "{}/fhepk_shortint.key",
        fpath
    ));
    tm.insert("fhepk_load", ts.duration());

    // encrypt
    let x = 1;
    let x_ct: tfhe::shortint::Ciphertext = fhepk.encrypt_by_public_key(x); //////////
    tm.insert("encrypt_by_public_key", ts.duration_and_reset());
    mind_sdk_fhe::io::write(&x_ct, &format!("{}/ct_u8_shortint.txt", fpath)).unwrap(); ///////////////
    tm.insert("ct_save", ts.duration_and_reset());

    // check encrypted filesize
    let fp = &format!("{}/ct_u8_shortint.txt", fpath);
    let fsize = &format!(
        " fpath: {}, fsize: {}",
        fp,
        mind_sdk_fhe::util::get_file_size(fp)
    );
    tm.insert(fsize, ts.duration_and_reset());

    let x_ct: tfhe::shortint::Ciphertext =
        mind_sdk_fhe::io::read(&format!("{}/ct_u8_shortint.txt", fpath)).unwrap(); ///////////
    tm.insert("ct_load", ts.duration_and_reset());

    // local ck to do compute
    let fheck = mind_sdk_fhe::FheShortint::new_from_compute_key_local(&format!(
        "{}/fheck_shortint.key",
        fpath
    ));
    tm.insert("fheck_load", ts.duration_and_reset());

    let z_ct = fheck
        .compute_key
        .as_ref()
        .unwrap()
        .unchecked_add(&x_ct, &x_ct);
    tm.insert("unchecked_add", ts.duration_and_reset());

    // local sk to decrpt
    let fhesk = mind_sdk_fhe::FheShortint::new_from_private_key_local(&format!(
        "{}/fhesk_shortint.key",
        fpath
    ));
    tm.insert("fhesk_load", ts.duration_and_reset());

    let z_pt: u64 = fhesk.decrypt_by_private_key(&z_ct); //////////////
    tm.insert("decrypt", ts.duration_and_reset());

    println!(
        "pt: {:?}, ct: {:?}, match: {}, bin: {:#066b}",
        x + x,
        &z_pt,
        (x + x) == (z_pt % 4),
        &z_pt
    );
    tm.pprint();
}

/*

0 0 => 0
0 0 1 => 0
0 0 1 1 1 => 1
0 0 0 1 1 => 0

*/
#[function_name::named]
pub fn test_u8_unchecked_add_loop() {
    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    ts.reset();
    let fhepk = mind_sdk_fhe::FheShortint::new_from_public_key_local(&format!(
        "{}/fhepk_shortint.key",
        fpath
    ));
    tm.insert("fhepk_load", ts.duration());

    let fhesk = mind_sdk_fhe::FheShortint::new_from_private_key_local(&format!(
        "{}/fhesk_shortint.key",
        fpath
    ));
    tm.insert("fhesk_load", ts.duration_and_reset());

    // encrypt
    let x = 1;
    let x_ct: tfhe::shortint::Ciphertext = fhepk.encrypt_by_public_key(x); //////////
    tm.insert("encrypt_by_public_key", ts.duration_and_reset());
    mind_sdk_fhe::io::write(&x_ct, &format!("{}/ct_u8_shortint.txt", fpath)).unwrap(); ///////////////
    tm.insert("ct_save", ts.duration_and_reset());

    // check encrypted filesize
    let fp = &format!("{}/ct_u8_shortint.txt", fpath);
    let fsize = &format!(
        " fpath: {}, fsize: {}",
        fp,
        mind_sdk_fhe::util::get_file_size(fp)
    );
    tm.insert(fsize, ts.duration_and_reset());

    let x_ct: tfhe::shortint::Ciphertext =
        mind_sdk_fhe::io::read(&format!("{}/ct_u8_shortint.txt", fpath)).unwrap(); ///////////
    tm.insert("ct_load", ts.duration_and_reset());

    // local ck to do compute
    let fheck = mind_sdk_fhe::FheShortint::new_from_compute_key_local(&format!(
        "{}/fheck_shortint.key",
        fpath
    ));
    tm.insert("fheck_load", ts.duration_and_reset());

    let z_ct = fheck
        .compute_key
        .as_ref()
        .unwrap()
        .unchecked_add(&x_ct, &x_ct);
    tm.insert("unchecked_add", ts.duration_and_reset());
    let mut z_ct = fheck
        .compute_key
        .as_ref()
        .unwrap()
        .unchecked_add(&z_ct, &x_ct);
    for _i in 0..100 {
        z_ct = fheck
            .compute_key
            .as_ref()
            .unwrap()
            .unchecked_add(&z_ct, &x_ct);
        let z_pt = fhesk.decrypt_by_private_key(&z_ct); //////////////
        println!("i: {:#?}, ct: {:#?}", _i, z_pt);
    }
    tm.insert("unchecked_add_loop", ts.duration_and_reset());

    // local sk to decrpt
    let z_pt: u64 = fhesk.decrypt_by_private_key(&z_ct); //////////////
    tm.insert("decrypt", ts.duration_and_reset());

    println!(
        "pt: {:?}, ct: {:?}, match: {}, bin: {:#066b}",
        x + x,
        &z_pt,
        (x + x) == (z_pt % 4),
        &z_pt
    );
    tm.pprint();
}

pub fn main() {
    //test_fhekeys_generation();
    //test_u8_checked_add();
    //test_u8_unchecked_add();
    test_u8_unchecked_add_loop();
}
