use function_name;
use tfhe::integer::IntegerRadixCiphertext;

#[function_name::named]
pub fn test_shift_and_seemessage_bits_change_shortint() {
    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    ts.reset();
    let fhepk_shortint =
        mind_sdk_fhe::FheShortint::new_from_public_key_local(&format!("{}/fhepk.key", fpath));
    tm.insert("fhepk_int", ts.duration_and_reset());

    let x = 3;
    let mut x_ct_shortint: tfhe::shortint::Ciphertext =
        fhepk_shortint.encrypt_by_public_key(x as u64); //////////
    tm.insert("encrypt_by_public_key_shortint", ts.duration_and_reset());

    let fheck_shortint =
        mind_sdk_fhe::FheShortint::new_from_compute_key_local(&format!("{}/fheck.key", fpath));
    let fhesk_shortint =
        mind_sdk_fhe::FheShortint::new_from_private_key_local(&format!("{}/fhesk.key", fpath));

    println!("shortint checked_scalar_left_shift");
    for i in 0..32 {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let ct_shifted = fheck_shortint
                .compute_key
                .as_ref()
                .unwrap()
                .checked_scalar_left_shift(&mut x_ct_shortint, i)
                .unwrap();
            println!(
                "{} {} {:#066b} {:#066b} {:?}",
                i,
                x,
                x,
                fhesk_shortint.decrypt_by_private_key(&ct_shifted),
                ts.duration_and_reset()
            );
        }));
        match result {
            Ok(v) => v,
            Err(v) => break,
        }
    }

    println!("shortint unchecked_scalar_left_shift");
    for i in 0..32 {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let ct_shifted = fheck_shortint
                .compute_key
                .as_ref()
                .unwrap()
                .unchecked_scalar_left_shift(&x_ct_shortint, i);
            println!(
                "{} {} {:#066b} {:#066b} {:?}",
                i,
                x,
                x,
                fhesk_shortint.decrypt_by_private_key(&ct_shifted),
                ts.duration_and_reset()
            );
        }));
        match result {
            Ok(v) => v,
            Err(v) => break,
        }
    }

    println!("shortint smart_scalar_left_shift");
    for i in 0..32 {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let ct_shifted = fheck_shortint
                .compute_key
                .as_ref()
                .unwrap()
                .smart_scalar_left_shift(&mut x_ct_shortint, i);
            println!(
                "{} {} {:#066b} {:#066b} {:?}",
                i,
                x,
                x,
                fhesk_shortint.decrypt_by_private_key(&ct_shifted),
                ts.duration_and_reset()
            );
        }));
        match result {
            Ok(v) => v,
            Err(v) => break,
        }
    }
}

#[function_name::named]
pub fn test_shift_and_seemessage_bits_change_int() {
    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    ts.reset();
    let fhepk_shortint =
        mind_sdk_fhe::FheInt::new_from_public_key_local(&format!("{}/fhepk.key", fpath));
    tm.insert("fhepk_int", ts.duration_and_reset());

    let x = 3;
    let mut x_ct_shortint: tfhe::integer::RadixCiphertext =
        fhepk_shortint.encrypt_by_public_key(x as u64); //////////
    tm.insert("encrypt_by_public_key_shortint", ts.duration_and_reset());

    let fheck_shortint =
        mind_sdk_fhe::FheInt::new_from_compute_key_local(&format!("{}/fheck.key", fpath));
    let fhesk_shortint =
        mind_sdk_fhe::FheInt::new_from_private_key_local(&format!("{}/fhesk.key", fpath));

    println!("int scalar_left_shift_parallelized");
    for i in 0..32 {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let ct_shifted = fheck_shortint
                .compute_key
                .as_ref()
                .unwrap()
                .scalar_left_shift_parallelized(&mut x_ct_shortint, i);
            println!(
                "{} {} {:#066b} {:#066b} {:?}",
                i,
                x,
                x,
                fhesk_shortint.decrypt_by_private_key::<u64>(&ct_shifted),
                ts.duration_and_reset()
            );
        }));
        match result {
            Ok(v) => v,
            Err(v) => break,
        }
    }

    println!("int unchecked_scalar_left_shift");
    for i in 0..32 {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let ct_shifted = fheck_shortint
                .compute_key
                .as_ref()
                .unwrap()
                .unchecked_scalar_left_shift(&x_ct_shortint, i);
            println!(
                "{} {} {:#066b} {:#066b} {:?}",
                i,
                x,
                x,
                fhesk_shortint.decrypt_by_private_key::<u64>(&ct_shifted),
                ts.duration_and_reset()
            );
        }));
        match result {
            Ok(v) => v,
            Err(v) => break,
        }
    }

    /*
    println!("int smart_left_shift_parallelized");
    for i in 0..32 {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let ct_shifted = fheck_shortint.compute_key.as_ref().unwrap().smart_left_shift_parallelized(&mut x_ct_shortint, i);
            println!("{} {} {:#066b} {:#066b} {:?}", i, x, x, fhesk_shortint.decrypt_by_private_key(&ct_shifted), ts.duration_and_reset());
        }));
        match result {Ok(v) => v, Err(v) => break,}
    }
    */
}

#[function_name::named]
pub fn test_bits_to_bytes() {
    println!("\n== function: {} ==", function_name!());
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    let fpath = "./data";

    let msg = 1000; //22;

    ts.reset();
    let fhepk_shortint =
        mind_sdk_fhe::FheShortint::new_from_public_key_local(&format!("{}/fhepk.key", fpath));
    let fhesk_shortint =
        mind_sdk_fhe::FheShortint::new_from_private_key_local(&format!("{}/fhesk.key", fpath));
    let fhepk_int =
        mind_sdk_fhe::FheInt::new_from_public_key_local(&format!("{}/fhepk.key", fpath));
    let fhesk_int =
        mind_sdk_fhe::FheInt::new_from_private_key_local(&format!("{}/fhesk.key", fpath));
    tm.insert("load_keys", ts.duration_and_reset());

    // clear -> ct_int -> block_cts -> block_pts
    let ct_int: tfhe::integer::RadixCiphertext = fhepk_int.encrypt_by_public_key(msg as u8); //////////
    let cts_int = ct_int.into_blocks();
    let mut block_pts: Vec<u64> = Vec::new();
    for i in 0..cts_int.len() {
        let block_ct = &cts_int[i];
        let block_pt = fhesk_shortint.decrypt_by_private_key(&block_ct);
        block_pts.push(block_pt.clone());
        println!(
            "blocks: {}, {} {:#066b} {:?}",
            i,
            block_pt,
            block_pt,
            ts.duration_and_reset()
        );
    }
    println!("pt:{}, cts_int: {:?}", msg, block_pts);

    // block_pts -> blocks_cts -> ct_int -> clear
    let ct_int: tfhe::integer::RadixCiphertext = fhepk_shortint.pts_int_to_cts_int(&block_pts);
    let pt = fhesk_int.decrypt_by_private_key::<u64>(&ct_int);
    println!(
        "cts_int: {:?} pt: {} {}, {:#066b} {:?}",
        &block_pts,
        pt,
        pt % 256,
        pt,
        ts.duration_and_reset()
    );

    let mut block_cts: Vec<tfhe::shortint::Ciphertext> = Vec::new();
    for i in 0..block_pts.len() {
        let block_ct_shortint: tfhe::shortint::Ciphertext =
            fhepk_shortint.encrypt_by_public_key(block_pts[i]);
        block_cts.push(block_ct_shortint);
    }
    let ct_int: tfhe::integer::RadixCiphertext = fhepk_shortint.cts_bits_to_ct_int(&block_cts);
    let pt = fhesk_int.decrypt_by_private_key::<u64>(&ct_int);
    println!(
        "cts_int: {:?} pt: {} {}, {:#066b} {:?}",
        &block_pts,
        pt,
        msg % 256,
        pt,
        ts.duration_and_reset()
    );

    /*
    let fhesk_shortint = mind_sdk_fhe::FheShortint::new_from_private_key_local(&format!("{}/fhesk.key", fpath));
    let cts = ct_int.into_blocks();

    let block_cts: Vec<tfhe::shortint::Ciphertext> = Vec::new();
    let shift = 2;
    for i in 0..block_pts.len() {
        let x_ct_shortint: tfhe::shortint::Ciphertext = fhepk_shortint.encrypt_by_public_key(block_pts[i]);
        block_cts.push(x_ct_shortint);
    }
    let ct_int = fhepk_shortint.cts_bits_to_int(block_cts);
    let pt = fhesk_shortint.decrypt_by_private_key::<u64>(&ct_int);
    println!("pt: {}, ct: {} {:#066b} {:#066b} {:?}", msg, pt, msg, pt, ts.duration_and_reset());
    */
}

pub fn main() {
    //test_shift_and_seemessage_bits_change_shortint();
    //test_shift_and_seemessage_bits_change_int()
    test_bits_to_bytes();
}
