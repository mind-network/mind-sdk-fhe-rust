use tfhe::integer::IntegerCiphertext;

pub fn generate_fhe_keys_if_not_exist(fpath: &str) {
    let _ = crate::io::mkdir(fpath);
    let mut fhe = crate::FheGeneral::new();
    fhe.generate_keys_and_save_local_if_not_exist(fpath);
}

pub fn generate_fhe_keys(fpath: &str) -> (String, String, String) {
    let _ = crate::io::mkdir(fpath);
    let mut fhe = crate::FheGeneral::new();
    let (fp_private_key, fp_compute_key, fp_public_key) = fhe.generate_keys_and_save_local(fpath);
    return (fp_private_key, fp_compute_key, fp_public_key);
}

pub fn encrypt(fhe: &crate::FheInt, utype: &str, pt: u128) -> tfhe::integer::RadixCiphertext {
    let ct: tfhe::integer::RadixCiphertext = match utype {
        "u8" => fhe.encrypt_by_public_key_radix::<u8>(pt as u8, 4),
        "u16" => fhe.encrypt_by_public_key_radix::<u16>(pt as u16, 8),
        "u32" => fhe.encrypt_by_public_key_radix::<u32>(pt as u32, 16),
        "u64" => fhe.encrypt_by_public_key_radix::<u64>(pt as u64, 32),
        "u128" => fhe.encrypt_by_public_key_radix::<u128>(pt as u128, 128),
        _ => panic!("create_ciphertext_vector: data type must be one of [u8, u16, u32, u64, u128]"),
    };
    return ct;
}

pub fn encrypt_save(
    fhe: &crate::FheInt,
    utype: &str,
    pt: u128,
    fpath_to_save: &str,
) -> tfhe::integer::RadixCiphertext {
    let ct = encrypt(fhe, utype, pt);
    let _ = crate::io::write(ct.clone(), fpath_to_save);
    return ct;
}

pub fn load_decrypt(fhe: &crate::FheInt, fpath_to_load: &str) -> u128 {
    let ct: tfhe::integer::RadixCiphertext = crate::io::read(fpath_to_load).unwrap();
    let pt: u128 = fhe.decrypt_by_private_key(&ct);
    return pt;
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct FilePath {
    id: u128,
    fp: String,
}
#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct FilePathVector {
    cts: Vec<FilePath>,
}

pub fn cts_load_local(fp_cts: &str) -> Vec<tfhe::integer::RadixCiphertext> {
    let json_str = std::fs::read_to_string(fp_cts).unwrap();
    let json: crate::fhe_client::FilePathVector = serde_json::from_str(&json_str).unwrap();
    //println!("{}", std::any::type_name_of_val(&json));
    let mut cts: Vec<tfhe::integer::RadixCiphertext> = Vec::new();
    for fp_ct in json.cts {
        //println!("{:?} {} {}", vote, vote.fp, vote.order);
        let ct: tfhe::integer::RadixCiphertext = crate::io::read(&fp_ct.fp).unwrap();
        cts.push(ct.clone());
    }
    return cts;
}

pub fn cts_do_map(
    number_of_group: usize,
    cts: &Vec<tfhe::integer::RadixCiphertext>,
) -> std::collections::HashMap<usize, Vec<tfhe::integer::RadixCiphertext>> {
    let mut cts_hm: std::collections::HashMap<usize, Vec<tfhe::integer::RadixCiphertext>> =
        std::collections::HashMap::new();
    for i in 0..cts.len() {
        let x = i % number_of_group; // decide which group to put
        let hm_key = x; // as usize;
        if !&cts_hm.contains_key(&hm_key) {
            let _ = &cts_hm.insert(hm_key, Vec::<tfhe::integer::RadixCiphertext>::new());
        }
        let _ = &cts_hm.get_mut(&hm_key).unwrap().push(cts[i].clone());
    }
    //mindsdk::util::pprint_ct::<usize, Vec<u64>>(pts_hm.clone());
    return cts_hm;
}

pub fn pts_do_map<T: Clone>(
    bits_groups: usize,
    pts: &Vec<T>,
) -> std::collections::HashMap<usize, Vec<T>> {
    let mut pts_hm: std::collections::HashMap<usize, Vec<T>> = std::collections::HashMap::new();
    for i in 0..pts.len() {
        let x = i % bits_groups;
        let hm_key = x; // as usize;
        if !&pts_hm.contains_key(&hm_key) {
            let _ = &pts_hm.insert(hm_key.clone(), Vec::<T>::new());
        }
        let _ = &pts_hm.get_mut(&hm_key).unwrap().push(pts[i].clone());
    }
    //mindsdk::util::pprint_ct::<usize, Vec<u64>>(pts_hm.clone());
    return pts_hm;
}

pub fn cts_vector_do_unchecked_add(
    cts: &Vec<tfhe::integer::RadixCiphertext>,
    fheck: &crate::FheInt,
) -> tfhe::integer::RadixCiphertext {
    if cts.len() == 0 {
        println!("cts.len() == 0 in cts_vector_do_unchecked_add");
        log::error!("cts.len() == 0 in cts_vector_do_unchecked_add");
        let ct = fheck
            .compute_key
            .as_ref()
            .unwrap()
            .create_trivial_zero_radix(4);
        return ct;
    }
    let mut ct_computed = cts[0].clone();
    for j in 0..cts.len() {
        if j != 0 {
            ct_computed = fheck
                .compute_key
                .as_ref()
                .unwrap()
                .unchecked_add(&ct_computed, &cts[j]);
        }
    }
    return ct_computed;
}

pub fn cts_do_reduce(
    number_of_group: usize,
    cts_hm: &std::collections::HashMap<usize, Vec<tfhe::integer::RadixCiphertext>>,
    fheck: &crate::FheInt,
) -> Vec<tfhe::integer::RadixCiphertext> {
    let mut cts_computed: Vec<tfhe::integer::RadixCiphertext> = Vec::with_capacity(number_of_group);
    for i in 0..number_of_group {
        if cts_hm.len() == 0 {
        } else {
            let ct_computed = cts_vector_do_unchecked_add(&cts_hm[&i], &fheck);
            cts_computed.push(ct_computed);
        }
    }
    return cts_computed;
}

pub fn cts_do_combine(
    number_of_group: usize,
    total_number_of_bits: usize,
    cts_computed: &Vec<tfhe::integer::RadixCiphertext>,
    _fheck: &crate::FheInt,
) -> tfhe::integer::RadixCiphertext {
    let mut cts_combine: Vec<tfhe::shortint::Ciphertext> = Vec::with_capacity(total_number_of_bits);
    let bits = total_number_of_bits / number_of_group / 2; // one block contains 2 bits
    for i in 0..cts_computed.len() {
        let blocks = cts_computed[i].blocks();
        let blocks = &blocks[0..bits];
        for block in blocks {
            cts_combine.push(block.clone());
        }
    }
    let cts_computed_int: tfhe::integer::RadixCiphertext =
        tfhe::integer::RadixCiphertext::from_blocks(cts_combine.clone());
    return cts_computed_int;
}

///////////////////////////////////////////////////////////////////////////////
pub async fn fhe_decrypt(ct: &tfhe::integer::RadixCiphertext, fhe: &crate::FheInt) -> u64 {
    let random_int: u64 = fhe.decrypt_by_private_key(ct); //sum.clone().decrypt(&client_key);
    log::info!("fhe_decrypt and get random_int: {:?}", random_int);
    return random_int;
}
