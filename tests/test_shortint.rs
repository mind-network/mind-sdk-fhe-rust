#[cfg(test)]
mod tests {

    #[test]
    #[function_name::named]
    pub fn fhekeys_general_run_in_memory() {
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
        tm.insert("encrypt_by_pk", ts.duration_and_reset());

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

        assert_eq!(x + x, z_pt % 4); // "FheGeneral test on key, encrypt, compute, decrypt",
    }
}
