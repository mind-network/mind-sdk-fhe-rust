use function_name;


#[function_name::named]
pub fn test_casting_from_general_to_int_to_shortint() {
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

    let z_ct = fhe.compute_key.as_ref().unwrap().checked_add(&x_ct, &x_ct).unwrap();
    tm.insert("checked_add", ts.duration_and_reset());

    let z_pt:u64 = fhe.decrypt_by_private_key(&z_ct); //////////////
    tm.insert("decrypt", ts.duration_and_reset());

    println!("pt: {:?}, ct: {:?}, match: {}, bin: {:#066b}", x+x, &z_pt, (x+x)==(z_pt), &z_pt);
    tm.pprint();
}

/* no work
#[function_name::named]
pub fn test_casting_from_shortint_to_int_to_general() {
    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::TimeDuration::new();
    let mut tm = mind_sdk_fhe::TimeMessage::new();

    ts.reset();
    let mut fhe_general = mind_sdk_fhe::FheGeneral::default();
    fhe_general.new_in_memory();
    tm.insert("fhe_general gen", ts.duration());

    let fhe_int = mind_sdk_fhe::FheInt::from(fhe_general);
    tm.insert("fhe_int gen", ts.duration());

    let fhe = mind_sdk_fhe::FheShortint::from(fhe_int);
    tm.insert("fhe_int gen", ts.duration());

    let fhe_int: mind_sdk_fhe::FheInt = fhe.into();
    let fhe: mind_sdk_fhe::FheGeneral = fhe_int.into();

    let x = 2;
    let x_ct: tfhe::FheUint8 = fhe.encrypt_by_public_key::<u8, tfhe::FheUint8>(x); //////////
    tm.insert("encrypt_by_public_key", ts.duration_and_reset());

    tfhe::set_server_key(fhe.compute_key.clone().unwrap());
    tm.insert("set_server_key", ts.duration_and_reset());

    let z_ct = &x_ct + &x_ct;
    tm.insert("+", ts.duration_and_reset());

    let z_pt:u8 = fhe.decrypt_by_private_key::<tfhe::FheUint8, u8>(&z_ct); //////////////
    tm.insert("decrypt", ts.duration_and_reset());

    println!("pt: {:?}, ct: {:?}, match: {}, bin: {:#066b}", x+x, &z_pt, (x+x)==(z_pt), &z_pt);
    tm.pprint();
}
*/


#[function_name::named]
pub fn test_resue_general_public_key() {
    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    ts.reset();
    let fhepk_general = mind_sdk_fhe::FheGeneral::new_from_public_key_local(&format!("{}/fhepk.key", fpath));
    tm.insert("fhepk_int", ts.duration_and_reset());

    ts.reset();
    let fhepk_int = mind_sdk_fhe::FheInt::new_from_public_key_local(&format!("{}/fhepk.key", fpath));
    tm.insert("fhepk_int", ts.duration_and_reset());

    ts.reset();
    let fhepk_shortint = mind_sdk_fhe::FheShortint::new_from_public_key_local(&format!("{}/fhepk.key", fpath));
    tm.insert("fhepk_int", ts.duration_and_reset());

    let x = 1;

    let x_ct_general: tfhe::FheUint8 = fhepk_general.encrypt_by_public_key::<u8, tfhe::FheUint8>(x); //////////
    tm.insert("encrypt_by_public_key_general", ts.duration_and_reset());

    let x_ct_int: tfhe::integer::RadixCiphertext = fhepk_int.encrypt_by_public_key::<u8>(x); //////////
    tm.insert("encrypt_by_public_key_int", ts.duration_and_reset());

    let x_ct_shortint: tfhe::shortint::Ciphertext = fhepk_shortint.encrypt_by_public_key(x as u64); //////////
    tm.insert("encrypt_by_public_key_shortint", ts.duration_and_reset());

    let fhesk_general = mind_sdk_fhe::FheGeneral::new_from_private_key_local(&format!("{}/fhesk.key", fpath));
    let z_pt:u64 = fhesk_general.decrypt_by_private_key(&x_ct_general); //////////////
    tm.insert("decrypt int {}", ts.duration_and_reset());
    println!("decrypt: {} {}", x, z_pt);

    let fhesk_int = mind_sdk_fhe::FheInt::new_from_private_key_local(&format!("{}/fhesk_int.key", fpath));
    let z_pt:u64 = fhesk_int.decrypt_by_private_key(&x_ct_int); //////////////
    tm.insert("decrypt int {}", ts.duration_and_reset());
    println!("decrypt: {} {}", x, z_pt);

    let fhesk_shortint = mind_sdk_fhe::FheShortint::new_from_private_key_local(&format!("{}/fhesk_shortint.key", fpath));
    let z_pt:u64 = fhesk_shortint.decrypt_by_private_key(&x_ct_shortint); //////////////
    tm.insert("decrypt int {}", ts.duration_and_reset());
    println!("decrypt: {} {}", x, z_pt);

}

#[function_name::named]
pub fn test_resue_general_private_key() {
    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    ts.reset();
    let fhepk_general = mind_sdk_fhe::FheGeneral::new_from_public_key_local(&format!("{}/fhepk.key", fpath));
    tm.insert("fhepk_int", ts.duration_and_reset());

    ts.reset();
    let fhepk_int = mind_sdk_fhe::FheInt::new_from_public_key_local(&format!("{}/fhepk_int.key", fpath));
    tm.insert("fhepk_int", ts.duration_and_reset());

    ts.reset();
    let fhepk_shortint = mind_sdk_fhe::FheShortint::new_from_public_key_local(&format!("{}/fhepk_shortint.key", fpath));
    tm.insert("fhepk_int", ts.duration_and_reset());

    let x = 1;

    let x_ct_general: tfhe::FheUint8 = fhepk_general.encrypt_by_public_key::<u8, tfhe::FheUint8>(x); //////////
    tm.insert("encrypt_by_public_key_general", ts.duration_and_reset());

    let x_ct_int: tfhe::integer::RadixCiphertext = fhepk_int.encrypt_by_public_key::<u8>(x); //////////
    tm.insert("encrypt_by_public_key_int", ts.duration_and_reset());

    let x_ct_shortint: tfhe::shortint::Ciphertext = fhepk_shortint.encrypt_by_public_key(x as u64); //////////
    tm.insert("encrypt_by_public_key_shortint", ts.duration_and_reset());

    let fhesk_general = mind_sdk_fhe::FheGeneral::new_from_private_key_local(&format!("{}/fhesk.key", fpath));
    let z_pt:u64 = fhesk_general.decrypt_by_private_key(&x_ct_general); //////////////
    tm.insert("decrypt int {}", ts.duration_and_reset());
    println!("decrypt: {} {}", x, z_pt);

    let fhesk_int = mind_sdk_fhe::FheInt::new_from_private_key_local(&format!("{}/fhesk.key", fpath));
    let z_pt:u64 = fhesk_int.decrypt_by_private_key(&x_ct_int); //////////////
    tm.insert("decrypt int {}", ts.duration_and_reset());
    println!("decrypt: {} {}", x, z_pt);

    let fhesk_shortint = mind_sdk_fhe::FheShortint::new_from_private_key_local(&format!("{}/fhesk.key", fpath));
    let z_pt:u64 = fhesk_shortint.decrypt_by_private_key(&x_ct_shortint); //////////////
    tm.insert("decrypt int {}", ts.duration_and_reset());
    println!("decrypt: {} {}", x, z_pt);

}


#[function_name::named]
pub fn test_resue_general_compute_key() {
    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    ts.reset();
    let fhepk_general = mind_sdk_fhe::FheGeneral::new_from_public_key_local(&format!("{}/fhepk.key", fpath));
    tm.insert("fhepk_int", ts.duration_and_reset());

    ts.reset();
    let fhepk_int = mind_sdk_fhe::FheInt::new_from_public_key_local(&format!("{}/fhepk_int.key", fpath));
    tm.insert("fhepk_int", ts.duration_and_reset());

    ts.reset();
    let fhepk_shortint = mind_sdk_fhe::FheShortint::new_from_public_key_local(&format!("{}/fhepk_shortint.key", fpath));
    tm.insert("fhepk_int", ts.duration_and_reset());

    let x = 1;

    let x_ct_general: tfhe::FheUint8 = fhepk_general.encrypt_by_public_key::<u8, tfhe::FheUint8>(x); //////////
    tm.insert("encrypt_by_public_key_general", ts.duration_and_reset());

    let x_ct_int: tfhe::integer::RadixCiphertext = fhepk_int.encrypt_by_public_key::<u8>(x); //////////
    tm.insert("encrypt_by_public_key_int", ts.duration_and_reset());

    let x_ct_shortint: tfhe::shortint::Ciphertext = fhepk_shortint.encrypt_by_public_key(x as u64); //////////
    tm.insert("encrypt_by_public_key_shortint", ts.duration_and_reset());


    let fheck_general = mind_sdk_fhe::FheGeneral::new_from_compute_key_local(&format!("{}/fheck.key", fpath));
    tfhe::set_server_key(fheck_general.compute_key.clone().unwrap());
    let z_ct_general = &x_ct_general + &x_ct_general;

    let fheck_int = mind_sdk_fhe::FheInt::new_from_compute_key_local(&format!("{}/fheck.key", fpath));
    let z_ct_int = fheck_int.compute_key.as_ref().unwrap().checked_add(&x_ct_int, &x_ct_int).unwrap();

    let fheck_shortint = mind_sdk_fhe::FheShortint::new_from_compute_key_local(&format!("{}/fheck.key", fpath));
    let z_ct_shortint = fheck_shortint.compute_key.as_ref().unwrap().checked_add(&x_ct_shortint, &x_ct_shortint).unwrap();


    let fhesk_general = mind_sdk_fhe::FheGeneral::new_from_private_key_local(&format!("{}/fhesk.key", fpath));
    let z_pt:u64 = fhesk_general.decrypt_by_private_key(&z_ct_general); //////////////
    tm.insert("decrypt int {}", ts.duration_and_reset());
    println!("decrypt: {} {}", x+x, z_pt);

    let fhesk_int = mind_sdk_fhe::FheInt::new_from_private_key_local(&format!("{}/fhesk_int.key", fpath));
    let z_pt:u64 = fhesk_int.decrypt_by_private_key(&z_ct_int); //////////////
    tm.insert("decrypt int {}", ts.duration_and_reset());
    println!("decrypt: {} {}", x+x, z_pt);

    let fhesk_shortint = mind_sdk_fhe::FheShortint::new_from_private_key_local(&format!("{}/fhesk_shortint.key", fpath));
    let z_pt:u64 = fhesk_shortint.decrypt_by_private_key(&z_ct_shortint); //////////////
    tm.insert("decrypt int {}", ts.duration_and_reset());
    println!("decrypt: {} {}", x+x, z_pt);
}


#[function_name::named]
pub fn test_resue_public_key_private_key_compute_key() {
    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    ts.reset();
    let fhepk_general = mind_sdk_fhe::FheGeneral::new_from_public_key_local(&format!("{}/fhepk.key", fpath));
    tm.insert("fhepk_int", ts.duration_and_reset());

    ts.reset();
    let fhepk_int = mind_sdk_fhe::FheInt::new_from_public_key_local(&format!("{}/fhepk.key", fpath));
    tm.insert("fhepk_int", ts.duration_and_reset());

    ts.reset();
    let fhepk_shortint = mind_sdk_fhe::FheShortint::new_from_public_key_local(&format!("{}/fhepk.key", fpath));
    tm.insert("fhepk_int", ts.duration_and_reset());

    let x = 1;

    let x_ct_general: tfhe::FheUint8 = fhepk_general.encrypt_by_public_key::<u8, tfhe::FheUint8>(x); //////////
    tm.insert("encrypt_by_public_key_general", ts.duration_and_reset());

    let x_ct_int: tfhe::integer::RadixCiphertext = fhepk_int.encrypt_by_public_key::<u8>(x); //////////
    tm.insert("encrypt_by_public_key_int", ts.duration_and_reset());

    let x_ct_shortint: tfhe::shortint::Ciphertext = fhepk_shortint.encrypt_by_public_key(x as u64); //////////
    tm.insert("encrypt_by_public_key_shortint", ts.duration_and_reset());


    let fheck_general = mind_sdk_fhe::FheGeneral::new_from_compute_key_local(&format!("{}/fheck.key", fpath));
    tfhe::set_server_key(fheck_general.compute_key.clone().unwrap());
    ts.reset();
    let z_ct_general = &x_ct_general + &x_ct_general;
    tm.insert("compute_by_general", ts.duration_and_reset());

    let fheck_int = mind_sdk_fhe::FheInt::new_from_compute_key_local(&format!("{}/fheck.key", fpath));
    ts.reset();
    let z_ct_int = fheck_int.compute_key.as_ref().unwrap().checked_add(&x_ct_int, &x_ct_int).unwrap();
    tm.insert("compute_by_int", ts.duration_and_reset());

    let fheck_shortint = mind_sdk_fhe::FheShortint::new_from_compute_key_local(&format!("{}/fheck.key", fpath));
    ts.reset();
    let z_ct_shortint = fheck_shortint.compute_key.as_ref().unwrap().checked_add(&x_ct_shortint, &x_ct_shortint).unwrap();
    tm.insert("compute_by_shortint", ts.duration_and_reset());


    let fhesk_general = mind_sdk_fhe::FheGeneral::new_from_private_key_local(&format!("{}/fhesk.key", fpath));
    let z_pt:u64 = fhesk_general.decrypt_by_private_key(&z_ct_general); //////////////
    tm.insert("decrypt int {}", ts.duration_and_reset());
    println!("decrypt: {} {}", x+x, z_pt);

    let fhesk_int = mind_sdk_fhe::FheInt::new_from_private_key_local(&format!("{}/fhesk.key", fpath));
    let z_pt:u64 = fhesk_int.decrypt_by_private_key(&z_ct_int); //////////////
    tm.insert("decrypt int {}", ts.duration_and_reset());
    println!("decrypt: {} {}", x+x, z_pt);

    let fhesk_shortint = mind_sdk_fhe::FheShortint::new_from_private_key_local(&format!("{}/fhesk.key", fpath));
    let z_pt:u64 = fhesk_shortint.decrypt_by_private_key(&z_ct_shortint); //////////////
    tm.insert("decrypt int {}", ts.duration_and_reset());
    println!("decrypt: {} {}", x+x, z_pt);
}


#[function_name::named]
pub fn test_ciphertext_cast_int_to_shortint() {
    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    ts.reset();
    let fhepk_int = mind_sdk_fhe::FheInt::new_from_public_key_local(&format!("{}/fhepk.key", fpath));
    tm.insert("fhepk_int", ts.duration_and_reset());

    ts.reset();
    let fhepk_shortint = mind_sdk_fhe::FheShortint::new_from_public_key_local(&format!("{}/fhepk.key", fpath));
    tm.insert("fhepk_int", ts.duration_and_reset());

    let x = 1;

    let x_ct_int: tfhe::integer::RadixCiphertext = fhepk_int.encrypt_by_public_key::<u8>(x); //////////
    tm.insert("encrypt_by_public_key_int", ts.duration_and_reset());

    let x_ct_shortint: tfhe::shortint::Ciphertext = fhepk_shortint.encrypt_by_public_key(x as u64); //////////
    tm.insert("encrypt_by_public_key_shortint", ts.duration_and_reset());

    let fp_int = &format!("{}/ct_u8_int.txt", fpath); 
    mind_sdk_fhe::io::write(&x_ct_int, fp_int).unwrap(); ///////////////
    tm.insert("ct_save_int", ts.duration_and_reset());
    let fp_shortint = &format!("{}/ct_u8_shortint.txt", fpath);
    mind_sdk_fhe::io::write(&x_ct_shortint, fp_shortint).unwrap(); /////////////// 
    tm.insert("ct_save_shortint", ts.duration_and_reset()); 

    let fp_int = &format!("{}/ct_u8_int.txt", fpath); 
    let x_ct_int: tfhe::integer::RadixCiphertext = mind_sdk_fhe::io::read(fp_int).unwrap(); ///////////
    tm.insert("ct_load_int",ts.duration_and_reset());
    let fp_shortint = &format!("{}/ct_u8_int.txt", fpath);
    let x_ct_shortint: tfhe::shortint::Ciphertext = mind_sdk_fhe::io::read(fp_shortint).unwrap(); ///////////
    tm.insert("ct_load_shortint",ts.duration_and_reset());

    let fsize_int = &format!(" fpath: {}, fsize: {}", fp_int, mind_sdk_fhe::util::get_file_size(fp_int));
    tm.insert(fsize_int, ts.duration_and_reset()); 
    let fsize_shortint = &format!(" fpath: {}, fsize: {}", fp_shortint, mind_sdk_fhe::util::get_file_size(fp_shortint));
    tm.insert(fsize_shortint, ts.duration_and_reset());  

    let fheck_int = mind_sdk_fhe::FheInt::new_from_compute_key_local(&format!("{}/fheck.key", fpath));
    let z_ct_int = fheck_int.compute_key.as_ref().unwrap().checked_add(&x_ct_int, &x_ct_int).unwrap();

    let fheck_shortint = mind_sdk_fhe::FheShortint::new_from_compute_key_local(&format!("{}/fheck.key", fpath));
    let z_ct_shortint = fheck_shortint.compute_key.as_ref().unwrap().checked_add(&x_ct_shortint, &x_ct_shortint).unwrap();

    let fhesk_int = mind_sdk_fhe::FheInt::new_from_private_key_local(&format!("{}/fhesk.key", fpath));
    let z_pt:u64 = fhesk_int.decrypt_by_private_key(&z_ct_int); //////////////
    tm.insert("decrypt int {}", ts.duration_and_reset());
    println!("decrypt: {} {}", x+x, z_pt);

    let fhesk_shortint = mind_sdk_fhe::FheShortint::new_from_private_key_local(&format!("{}/fhesk.key", fpath));
    let z_pt:u64 = fhesk_shortint.decrypt_by_private_key(&z_ct_shortint); //////////////
    tm.insert("decrypt int {}", ts.duration_and_reset());
    println!("decrypt: {} {}", x+x, z_pt);

    tm.pprint();
}


#[function_name::named]
pub fn test_ciphertext_cast_shortint_to_int() {
    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    ts.reset();
    let fhepk_int = mind_sdk_fhe::FheInt::new_from_public_key_local(&format!("{}/fhepk.key", fpath));
    tm.insert("fhepk_int", ts.duration_and_reset());

    ts.reset();
    let fhepk_shortint = mind_sdk_fhe::FheShortint::new_from_public_key_local(&format!("{}/fhepk.key", fpath));
    tm.insert("fhepk_int", ts.duration_and_reset());

    let x = 1;

    let x_ct_int: tfhe::integer::RadixCiphertext = fhepk_int.encrypt_by_public_key::<u8>(x); //////////
    tm.insert("encrypt_by_public_key_int", ts.duration_and_reset());

    let x_ct_shortint: tfhe::shortint::Ciphertext = fhepk_shortint.encrypt_by_public_key(x as u64); //////////
    tm.insert("encrypt_by_public_key_shortint", ts.duration_and_reset());

    let fp_int = &format!("{}/ct_u8_int.txt", fpath); 
    mind_sdk_fhe::io::write(&x_ct_int, fp_int).unwrap(); ///////////////
    tm.insert("ct_save_int", ts.duration_and_reset());
    let fp_shortint = &format!("{}/ct_u8_shortint.txt", fpath);
    mind_sdk_fhe::io::write(&x_ct_shortint, fp_shortint).unwrap(); /////////////// 
    tm.insert("ct_save_shortint", ts.duration_and_reset()); 

    let fp_int = &format!("{}/ct_u8_shortint.txt", fpath); 
    let x_ct_int: tfhe::integer::RadixCiphertext = mind_sdk_fhe::io::read(fp_int).unwrap(); ///////////
    tm.insert("ct_load_int",ts.duration_and_reset());
    let fp_shortint = &format!("{}/ct_u8_shortint.txt", fpath);
    let x_ct_shortint: tfhe::shortint::Ciphertext = mind_sdk_fhe::io::read(fp_shortint).unwrap(); ///////////
    tm.insert("ct_load_shortint",ts.duration_and_reset());

    let fsize_int = &format!(" fpath: {}, fsize: {}", fp_int, mind_sdk_fhe::util::get_file_size(fp_int));
    tm.insert(fsize_int, ts.duration_and_reset()); 
    let fsize_shortint = &format!(" fpath: {}, fsize: {}", fp_shortint, mind_sdk_fhe::util::get_file_size(fp_shortint));
    tm.insert(fsize_shortint, ts.duration_and_reset());  

    let fheck_int = mind_sdk_fhe::FheInt::new_from_compute_key_local(&format!("{}/fheck.key", fpath));
    let z_ct_int = fheck_int.compute_key.as_ref().unwrap().checked_add(&x_ct_int, &x_ct_int).unwrap();

    let fheck_shortint = mind_sdk_fhe::FheShortint::new_from_compute_key_local(&format!("{}/fheck.key", fpath));
    let z_ct_shortint = fheck_shortint.compute_key.as_ref().unwrap().checked_add(&x_ct_shortint, &x_ct_shortint).unwrap();

    let fhesk_int = mind_sdk_fhe::FheInt::new_from_private_key_local(&format!("{}/fhesk.key", fpath));
    let z_pt:u64 = fhesk_int.decrypt_by_private_key(&z_ct_int); //////////////
    tm.insert("decrypt int {}", ts.duration_and_reset());
    println!("decrypt: {} {}", x+x, z_pt);

    let fhesk_shortint = mind_sdk_fhe::FheShortint::new_from_private_key_local(&format!("{}/fhesk.key", fpath));
    let z_pt:u64 = fhesk_shortint.decrypt_by_private_key(&z_ct_shortint); //////////////
    tm.insert("decrypt int {}", ts.duration_and_reset());
    println!("decrypt: {} {}", x+x, z_pt);

    tm.pprint();
}

pub fn main() {
    test_casting_from_general_to_int_to_shortint();
    //test_casting_from_shortint_to_int_to_general();
    test_resue_general_public_key();
    test_resue_general_private_key();
    test_resue_general_compute_key();
    test_resue_public_key_private_key_compute_key();
    //test_ciphertext_cast_int_to_shortint(); // can not run, means ciphertext can not cast
    //test_ciphertext_cast_shortint_to_int(); // can not run, means ciphertext can not cast
}