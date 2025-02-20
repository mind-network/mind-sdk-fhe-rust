use function_name;

#[function_name::named]
pub fn test_new_in_memory() {
    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();

    ts.reset();
    let mut fhe = mind_sdk_fhe::FheGeneral::default();
    fhe.new_in_memory();
    tm.insert("fhepk_load", ts.duration());

    let x = 2;
    let x_ct: tfhe::FheUint8 = fhe.encrypt_by_public_key::<u8, tfhe::FheUint8>(x); //////////
    tm.insert("encrypt_by_public_key", ts.duration_and_reset());

    tfhe::set_server_key(fhe.compute_key.clone().unwrap());
    tm.insert("set_server_key", ts.duration_and_reset());

    let z_ct = &x_ct + &x_ct;
    tm.insert("+", ts.duration_and_reset());

    let z_pt: u8 = fhe.decrypt_by_private_key::<tfhe::FheUint8, u8>(&z_ct); //////////////
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

    let mut fhe = mind_sdk_fhe::FheGeneral::new();
    fhe.generate_keys_and_save_local_if_not_exist(fpath);
}

#[function_name::named]
pub fn test_u8() {
    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    ts.reset();
    let fhepk =
        mind_sdk_fhe::FheGeneral::new_from_public_key_local(&format!("{}/fhepk.key", fpath));
    tm.insert("fhepk_load", ts.duration());

    let x = 2;
    let x_ct: tfhe::FheUint8 = fhepk.encrypt_by_public_key::<u8, tfhe::FheUint8>(x); //////////
    tm.insert("encrypt_by_public_key", ts.duration_and_reset());
    mind_sdk_fhe::io::write(&x_ct, &format!("{}/ct_u8.txt", fpath)).unwrap(); ///////////////
    tm.insert("ct_save", ts.duration_and_reset());
    let x_ct: tfhe::FheUint8 = mind_sdk_fhe::io::read(&format!("{}/ct_u8.txt", fpath)).unwrap(); ///////////
    tm.insert("ct_load", ts.duration_and_reset());

    let fheck =
        mind_sdk_fhe::FheGeneral::new_from_compute_key_local(&format!("{}/fheck.key", fpath));
    tm.insert("fheck_load", ts.duration_and_reset());
    tfhe::set_server_key(fheck.compute_key.clone().unwrap());
    tm.insert("set_server_key", ts.duration_and_reset());

    let z_ct = &x_ct + &x_ct;
    tm.insert("+", ts.duration_and_reset());

    let fhesk =
        mind_sdk_fhe::FheGeneral::new_from_private_key_local(&format!("{}/fhesk.key", fpath));
    tm.insert("fhesk_load", ts.duration_and_reset());

    let z_pt: u8 = fhesk.decrypt_by_private_key::<tfhe::FheUint8, u8>(&z_ct); //////////////
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
    type U = tfhe::FheUint16;
    let t_typename = "u16";

    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    ts.reset();
    let fhepk =
        mind_sdk_fhe::FheGeneral::new_from_public_key_local(&format!("{}/fhepk.key", fpath));
    tm.insert("fhepk_load", ts.duration_and_reset());

    let x = 2 as T;
    let x_ct: U = fhepk.encrypt_by_public_key::<T, U>(x); //////////
    tm.insert("encrypt_by_public_key", ts.duration_and_reset());
    mind_sdk_fhe::io::write(&x_ct, &format!("{}/ct_{}.txt", fpath, t_typename)).unwrap(); ///////////////
    tm.insert("ct_save", ts.duration_and_reset());
    let x_ct: U = mind_sdk_fhe::io::read(&format!("{}/ct_{}.txt", fpath, t_typename)).unwrap(); ///////////
    tm.insert("ct_load", ts.duration_and_reset());

    let fheck =
        mind_sdk_fhe::FheGeneral::new_from_compute_key_local(&format!("{}/fheck.key", fpath));
    tm.insert("fheck_load", ts.duration_and_reset());
    tfhe::set_server_key(fheck.compute_key.clone().unwrap());
    tm.insert("set_server_key", ts.duration_and_reset());

    let z_ct = &x_ct + &x_ct;
    tm.insert("+", ts.duration_and_reset());
    let mut z_ct = &z_ct + &x_ct;
    for i in 0..1000 {
        z_ct = &z_ct + &x_ct;
    }
    tm.insert("+ loop", ts.duration_and_reset());

    let fhesk =
        mind_sdk_fhe::FheGeneral::new_from_private_key_local(&format!("{}/fhesk.key", fpath));
    tm.insert("fhesk_load", ts.duration_and_reset());

    let z_pt: T = fhesk.decrypt_by_private_key::<U, T>(&z_ct); //////////////
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
    type U = tfhe::FheUint128;
    let t_typename = "u16";

    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    ts.reset();
    let fhepk =
        mind_sdk_fhe::FheGeneral::new_from_public_key_local(&format!("{}/fhepk.key", fpath));
    tm.insert("fhepk_load", ts.duration_and_reset());

    let x = 2 as T;
    let x_ct: U = fhepk.encrypt_by_public_key::<T, U>(x); //////////
    tm.insert("encrypt_by_public_key", ts.duration_and_reset());
    mind_sdk_fhe::io::write(&x_ct, &format!("{}/ct_{}.txt", fpath, t_typename)).unwrap(); ///////////////
    tm.insert("ct_save", ts.duration_and_reset());
    let x_ct: U = mind_sdk_fhe::io::read(&format!("{}/ct_{}.txt", fpath, t_typename)).unwrap(); ///////////
    tm.insert("ct_load", ts.duration_and_reset());

    let fheck =
        mind_sdk_fhe::FheGeneral::new_from_compute_key_local(&format!("{}/fheck.key", fpath));
    tm.insert("fheck_load", ts.duration_and_reset());
    tfhe::set_server_key(fheck.compute_key.clone().unwrap());
    tm.insert("set_server_key", ts.duration_and_reset());

    let z_ct = &x_ct + &x_ct;
    tm.insert("+", ts.duration_and_reset());
    let mut z_ct = &z_ct + &x_ct;
    for i in 0..10 {
        z_ct = &z_ct + &x_ct;
    }
    tm.insert("+ loop", ts.duration_and_reset());

    let fhesk =
        mind_sdk_fhe::FheGeneral::new_from_private_key_local(&format!("{}/fhesk.key", fpath));
    tm.insert("fhesk_load", ts.duration_and_reset());

    let z_pt: T = fhesk.decrypt_by_private_key::<U, T>(&z_ct); //////////////
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
    //test_u128();
}
