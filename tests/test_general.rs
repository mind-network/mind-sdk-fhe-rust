#[cfg(test)]
mod tests {

    #[test]
    #[function_name::named]
    pub fn fhekeys_general_run_in_memory() {
        println!("\n== function: {} ==", function_name!());
        let mut ts = mind_sdk_fhe::util::TimeDuration::new();
        let mut tm = mind_sdk_fhe::util::TimeMessage::new();

        ts.reset();
        let mut fhe = mind_sdk_fhe::FheGeneral::default();
        fhe.new_in_memory();
        tm.insert("fhepk_load", ts.duration());

        let x = 2;
        let x_ct: tfhe::FheUint8 = fhe.encrypt_by_public_key::<u8, tfhe::FheUint8>(x); //////////
        tm.insert("encrypt_by_pk", ts.duration_and_reset());

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

        assert_eq!(x + x, z_pt); // "FheGeneral test on key, encrypt, compute, decrypt",
    }
}
