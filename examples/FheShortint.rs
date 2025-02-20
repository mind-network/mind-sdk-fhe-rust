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

    let fhe_int = mind_sdk_fhe::FheInt::from(fhe_general);
    tm.insert("fhe_int gen", ts.duration());

    let fhe = mind_sdk_fhe::FheShortint::from(fhe_int);
    tm.insert("fhe_int gen", ts.duration());

    let x = 1;
    let x_ct: tfhe::shortint::Ciphertext = fhe.encrypt_by_public_key(x); //////////
    tm.insert("encrypt_by_public_key", ts.duration_and_reset());

    let z_ct = fhe
        .compute_key
        .as_ref()
        .unwrap()
        .checked_add(&x_ct, &x_ct)
        .unwrap();
    tm.insert("checked_add", ts.duration_and_reset());

    let z_pt: u64 = fhe.decrypt_by_private_key(&z_ct); //////////////
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
}

#[function_name::named]
pub fn test_u8() {
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

    let x = 1;
    let x_ct: tfhe::shortint::Ciphertext = fhepk.encrypt_by_public_key(x); //////////
    tm.insert("encrypt_by_public_key", ts.duration_and_reset());
    mind_sdk_fhe::io::write(&x_ct, &format!("{}/ct_u8_shortint.txt", fpath)).unwrap(); ///////////////
    tm.insert("ct_save", ts.duration_and_reset());

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
pub fn test_u16() {
    //type T = u16;
    type U = tfhe::shortint::Ciphertext;
    let t_typename = "u16";

    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    ts.reset();
    let fhepk = mind_sdk_fhe::FheShortint::new_from_public_key_local(&format!(
        "{}/fhepk_shortint.key",
        fpath
    ));
    tm.insert("fhepk_load", ts.duration_and_reset());

    let x = 1;
    let x_ct: U = fhepk.encrypt_by_public_key(x); //////////
    tm.insert("encrypt_by_public_key", ts.duration_and_reset());
    mind_sdk_fhe::io::write(&x_ct, &format!("{}/ct_{}_shortint.txt", fpath, t_typename)).unwrap(); ///////////////
    tm.insert("ct_save", ts.duration_and_reset());

    let fp = &format!("{}/ct_{}_shortint.txt", fpath, t_typename);
    let fsize = &format!(
        " fpath: {}, fsize: {}",
        fp,
        mind_sdk_fhe::util::get_file_size(fp)
    );
    tm.insert(fsize, ts.duration_and_reset());

    let x_ct: U =
        mind_sdk_fhe::io::read(&format!("{}/ct_{}_shortint.txt", fpath, t_typename)).unwrap(); ///////////
    tm.insert("ct_load", ts.duration_and_reset());

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

    let fhesk = mind_sdk_fhe::FheShortint::new_from_private_key_local(&format!(
        "{}/fhesk_shortint.key",
        fpath
    ));
    tm.insert("fhesk_load", ts.duration_and_reset());

    let z_pt: u64 = fhesk.decrypt_by_private_key(&z_ct); //////////////
    tm.insert("decrypt", ts.duration_and_reset());

    let matched: bool = (x + x) == (z_pt % 4);
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
    //type T = u128;
    type U = tfhe::shortint::Ciphertext;
    let t_typename = "u128";

    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    ts.reset();
    let fhepk = mind_sdk_fhe::FheShortint::new_from_public_key_local(&format!(
        "{}/fhepk_shortint.key",
        fpath
    ));
    tm.insert("fhepk_load", ts.duration_and_reset());

    let x = 2;
    let x_ct: U = fhepk.encrypt_by_public_key(x); //////////
    tm.insert("encrypt_by_public_key", ts.duration_and_reset());
    mind_sdk_fhe::io::write(&x_ct, &format!("{}/ct_{}_shortint.txt", fpath, t_typename)).unwrap(); ///////////////
    tm.insert("ct_save", ts.duration_and_reset());

    let fp = &format!("{}/ct_{}_shortint.txt", fpath, t_typename);
    let fsize = &format!(
        " fpath: {}, fsize: {}",
        fp,
        mind_sdk_fhe::util::get_file_size(fp)
    );
    tm.insert(fsize, ts.duration_and_reset());

    let x_ct: U =
        mind_sdk_fhe::io::read(&format!("{}/ct_{}_shortint.txt", fpath, t_typename)).unwrap(); ///////////
    tm.insert("ct_load", ts.duration_and_reset());

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

    let fhesk = mind_sdk_fhe::FheShortint::new_from_private_key_local(&format!(
        "{}/fhesk_shortint.key",
        fpath
    ));
    tm.insert("fhesk_load", ts.duration_and_reset());

    let z_pt: u64 = fhesk.decrypt_by_private_key(&z_ct); //////////////
    tm.insert("decrypt", ts.duration_and_reset());

    let matched: bool = (x + x) == (z_pt % 4);
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
    test_new_in_memory();
    test_fhekeys_generation();
    test_u8();
    test_u16();
    test_u128();
}
