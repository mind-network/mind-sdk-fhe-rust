use function_name;

#[function_name::named]
pub fn test_zero_shortint() {
    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    ts.reset();
    let fhepk_shortint =
        mind_sdk_fhe::FheShortint::new_from_public_key_local(&format!("{}/fhepk.key", fpath));
    tm.insert("fhepk_int", ts.duration_and_reset());

    let x = 3;
    let ct_shortint: tfhe::shortint::Ciphertext = fhepk_shortint.encrypt_by_public_key(x as u64); //////////
    tm.insert("encrypt_by_public_key_shortint", ts.duration_and_reset());

    let fheck_shortint =
        mind_sdk_fhe::FheShortint::new_from_compute_key_local(&format!("{}/fheck.key", fpath));
    let zero_ct = fheck_shortint.get_zero_ct(ct_shortint);

    let fhesk_shortint =
        mind_sdk_fhe::FheShortint::new_from_private_key_local(&format!("{}/fhesk.key", fpath));
    let zero_pt = fhesk_shortint.decrypt_by_private_key(&zero_ct);

    println!("zero in shortint: {}", zero_pt);
}

#[function_name::named]
pub fn test_zero_int() {
    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    ts.reset();
    let fhepk_int =
        mind_sdk_fhe::FheInt::new_from_public_key_local(&format!("{}/fhepk.key", fpath));
    tm.insert("fhepk_int", ts.duration_and_reset());

    let x = 3;
    let ct_int: tfhe::integer::RadixCiphertext = fhepk_int.encrypt_by_public_key(x as u64); //////////
    tm.insert("encrypt_by_public_key_shortint", ts.duration_and_reset());

    let fheck_int =
        mind_sdk_fhe::FheInt::new_from_compute_key_local(&format!("{}/fheck.key", fpath));
    let zero_ct = fheck_int.get_zero_ct(ct_int);

    let fhesk_int =
        mind_sdk_fhe::FheInt::new_from_private_key_local(&format!("{}/fhesk.key", fpath));
    let zero_pt = fhesk_int.decrypt_by_private_key::<u64>(&zero_ct);

    println!("zero in shortint: {}", zero_pt);
}

pub fn main() {
    test_zero_shortint();
    test_zero_int();
}
