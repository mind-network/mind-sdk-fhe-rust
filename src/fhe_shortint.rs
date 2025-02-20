pub use crate::fhe_int::*;
pub use crate::FheInt;
use tfhe::integer::IntegerCiphertext;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct FheShortint {
    pub private_key: Option<tfhe::shortint::ClientKey>,
    pub compute_key: Option<tfhe::shortint::ServerKey>,
    pub public_key: Option<tfhe::shortint::CompactPublicKey>,
}

impl std::fmt::Display for FheShortint {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "FheShortint {{ private_key: {}, compute_key: {}, public_key: {} }}",
            self.private_key.is_some(),
            self.compute_key.is_some(),
            self.public_key.is_some()
        )
    }
}

impl Default for FheShortint {
    fn default() -> Self {
        Self {
            private_key: None,
            compute_key: None,
            public_key: None,
        }
    }
}

impl From<FheInt> for FheShortint {
    fn from(item: FheInt) -> Self {
        let mut private_key: Option<tfhe::shortint::ClientKey> = None;
        let mut compute_key: Option<tfhe::shortint::ServerKey> = None;
        let mut public_key: Option<tfhe::shortint::CompactPublicKey> = None;
        if item.private_key.is_some() {
            private_key = Some(private_key_convert_from_int_to_shortint(
                item.private_key.unwrap(),
            ));
        }
        if item.compute_key.is_some() {
            compute_key = Some(compute_key_convert_from_int_to_shortint(
                item.compute_key.unwrap(),
            ));
        }
        if item.public_key.is_some() {
            public_key = Some(public_key_convert_from_int_to_shortint(
                item.public_key.unwrap(),
            ));
        }
        Self {
            private_key: private_key,
            compute_key: compute_key,
            public_key: public_key,
        }
    }
}

impl FheShortint {
    pub fn new() -> Self {
        Self {
            private_key: None,
            compute_key: None,
            public_key: None,
        }
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn new_from_private_key_local(fpath: &str) -> Self {
        let private_key: tfhe::shortint::ClientKey = crate::io::read(fpath).unwrap();
        let private_key = Some(private_key);
        Self {
            private_key: private_key,
            compute_key: None,
            public_key: None,
        }
    }
    pub fn new_from_compute_key_local(fpath: &str) -> Self {
        let compute_key_int_compressed: tfhe::shortint::CompressedServerKey =
            crate::io::read(fpath).unwrap();
        let compute_key: tfhe::shortint::ServerKey = compute_key_int_compressed.decompress();
        let compute_key = Some(compute_key);
        Self {
            private_key: None,
            compute_key: compute_key,
            public_key: None,
        }
    }
    pub fn new_from_public_key_local(fpath: &str) -> Self {
        let public_key_int_compact: tfhe::shortint::CompactPublicKey =
            crate::io::read(fpath).unwrap();
        let public_key = Some(public_key_int_compact);
        Self {
            private_key: None,
            compute_key: None,
            public_key: public_key,
        }
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn new_from_private_key_general_local(fpath: &str) -> Self {
        let private_key_tfhe: tfhe::ClientKey = crate::io::read(fpath).unwrap();
        let private_key_int: tfhe::integer::ClientKey =
            private_key_convert_from_general_to_int(private_key_tfhe);
        let private_key_shortint: tfhe::shortint::ClientKey =
            private_key_convert_from_int_to_shortint(private_key_int);
        let private_key = Some(private_key_shortint);
        Self {
            private_key: private_key,
            compute_key: None,
            public_key: None,
        }
    }
    pub fn new_from_compute_key_general_local(fpath: &str) -> Self {
        let compute_key_general_compressed: tfhe::CompressedServerKey =
            crate::io::read(fpath).unwrap();
        let compute_key_tfhe: tfhe::ServerKey = compute_key_general_compressed.decompress();
        let compute_key_int: tfhe::integer::ServerKey =
            compute_key_convert_from_general_to_int(compute_key_tfhe);
        let compute_key_shortint: tfhe::shortint::ServerKey =
            compute_key_convert_from_int_to_shortint(compute_key_int);
        let compute_key = Some(compute_key_shortint);
        Self {
            private_key: None,
            compute_key: compute_key,
            public_key: None,
        }
    }
    pub fn new_from_public_key_general_local(fpath: &str) -> Self {
        let public_key_tfhe: tfhe::CompactPublicKey = crate::io::read(fpath).unwrap();
        let public_key_int: tfhe::integer::CompactPublicKey =
            public_key_convert_from_general_to_int(public_key_tfhe);
        let public_key_shortint: tfhe::shortint::CompactPublicKey =
            public_key_convert_from_int_to_shortint(public_key_int);
        let public_key = Some(public_key_shortint);
        Self {
            private_key: None,
            compute_key: None,
            public_key: public_key,
        }
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn private_key_load_local_and_convert_from_tfhe(
        &mut self,
        fpath: &str,
    ) -> tfhe::shortint::ClientKey {
        let private_key_tfhe: tfhe::ClientKey = crate::io::read(fpath).unwrap();
        let private_key_int: tfhe::integer::ClientKey =
            private_key_convert_from_general_to_int(private_key_tfhe);
        let private_key_shortint: tfhe::shortint::ClientKey =
            private_key_convert_from_int_to_shortint(private_key_int);
        return private_key_shortint;
    }
    pub fn private_key_save_local(&self, fpath: &str) {
        let _ = crate::io::write(self.private_key.as_ref().unwrap(), &fpath);
    }
    pub fn private_key_load_local(&mut self, fpath: &str) {
        let private_key: tfhe::shortint::ClientKey = crate::io::read(fpath).unwrap();
        let private_key = Some(private_key);
        self.private_key = private_key;
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn compute_key_compressed_load_local_and_convert_from_tfhe(
        &mut self,
        fpath: &str,
    ) -> tfhe::shortint::CompressedServerKey {
        let compute_key_compressed: tfhe::CompressedServerKey = crate::io::read(fpath).unwrap();
        let compute_key_int_compressed: tfhe::integer::CompressedServerKey =
            compute_key_compressed_convert_from_general_to_int(compute_key_compressed);
        let compute_key_shortint_compressed: tfhe::shortint::CompressedServerKey =
            compute_key_compressed_convert_from_int_to_shortint(compute_key_int_compressed);
        return compute_key_shortint_compressed;
    }
    pub fn compute_key_compressed_save_local(
        &self,
        compute_key_shortint_compressed: tfhe::shortint::CompressedServerKey,
        fpath: &str,
    ) {
        let _ = crate::io::write(compute_key_shortint_compressed, &fpath);
    }
    pub fn compute_key_compressed_load_local(&mut self, fpath: &str) {
        let compute_key_shortint_compressed: tfhe::shortint::CompressedServerKey =
            crate::io::read(fpath).unwrap();
        let compute_key: tfhe::shortint::ServerKey = compute_key_shortint_compressed.decompress();
        self.compute_key = Some(compute_key);
    }
    pub fn compute_key_load_local(&mut self, fpath: &str) {
        self.compute_key_compressed_load_local(fpath);
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn public_key_compressed_load_local_and_convert_from_tfhe(
        &mut self,
        fpath: &str,
    ) -> tfhe::shortint::CompressedPublicKey {
        let public_key_compressed: tfhe::CompressedPublicKey = crate::io::read(fpath).unwrap();
        let public_key_int_compressed: tfhe::integer::CompressedPublicKey =
            public_key_compressed_convert_from_general_to_int(public_key_compressed);
        let public_key_shortint_compressed: tfhe::shortint::CompressedPublicKey =
            public_key_compressed_convert_from_int_to_shortint(public_key_int_compressed);
        return public_key_shortint_compressed;
    }
    pub fn public_key_compressed_save_local(
        &self,
        public_key_shortint_compressed: tfhe::integer::CompressedPublicKey,
        fpath: &str,
    ) {
        let _ = crate::io::write(public_key_shortint_compressed, &fpath);
    }
    pub fn public_key_compressed_load_local(&mut self, fpath: &str) -> tfhe::shortint::PublicKey {
        let public_key_shortint_compressed: tfhe::shortint::CompressedPublicKey =
            crate::io::read(fpath).unwrap();
        let public_key: tfhe::shortint::PublicKey = public_key_shortint_compressed.decompress();
        return public_key;
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn public_key_compact_load_local_and_convert_from_tfhe(
        &mut self,
        fpath: &str,
    ) -> tfhe::shortint::CompactPublicKey {
        let public_key_compact: tfhe::CompactPublicKey = crate::io::read(fpath).unwrap();
        let public_key_int_compact: tfhe::integer::CompactPublicKey =
            public_key_compact_convert_from_general_to_int(public_key_compact);
        let public_key_shortint_compact: tfhe::shortint::CompactPublicKey =
            public_key_compact_convert_from_int_to_shortint(public_key_int_compact);
        return public_key_shortint_compact;
    }
    pub fn public_key_compact_save_local(
        &self,
        public_key_shortint_compact: tfhe::shortint::CompactPublicKey,
        fpath: &str,
    ) {
        let _ = crate::io::write(public_key_shortint_compact, &fpath);
    }
    pub fn public_key_compact_load_local(&mut self, fpath: &str) {
        let public_key_shortint_compact: tfhe::shortint::CompactPublicKey =
            crate::io::read(fpath).unwrap();
        self.public_key = Some(public_key_shortint_compact);
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn public_key_load_local(&mut self, fpath: &str) {
        self.public_key_compact_load_local(fpath);
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn generate_keys_and_save_local_if_not_exist(&mut self, fpath: &str) {
        let fpath_fhesk = &format!("{}/fhesk_shortint.key", &fpath);
        if !std::path::Path::new(&fpath_fhesk).exists() {
            println!("not exist and to create fhe keys");
            let private_key_shortint =
                self.private_key_load_local_and_convert_from_tfhe(&format!("{}/fhesk.key", fpath));
            let _ = crate::io::write(
                private_key_shortint,
                &format!("{}/fhesk_shortint.key", fpath),
            );

            let compute_key_shortint = self
                .compute_key_compressed_load_local_and_convert_from_tfhe(&format!(
                    "{}/fheck.key",
                    fpath
                ));
            let _ = crate::io::write(
                compute_key_shortint,
                &format!("{}/fheck_shortint.key", fpath),
            );

            let public_key_shortint = self.public_key_compact_load_local_and_convert_from_tfhe(
                &format!("{}/fhepk.key", fpath),
            );
            let _ = crate::io::write(
                public_key_shortint,
                &format!("{}/fhepk_shortint.key", fpath),
            );
        } else {
            println!("key exist and skip generation");
        }
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn encrypt_by_public_key(&self, num: u64) -> tfhe::shortint::Ciphertext
//where 
    //    T: std::marker::Copy,
    {
        // option 1
        let compact_list: tfhe::shortint::ciphertext::CompactCiphertextList = self
            .public_key
            .as_ref()
            .unwrap()
            .encrypt_iter([num].iter().copied());
        let expanded: Vec<tfhe::shortint::ciphertext::Ciphertext> = compact_list
            .expand(tfhe::shortint::ciphertext::ShortintCompactCiphertextListCastingMode::NoCasting)
            .unwrap();

        // option 2
        /*let ct: &tfhe::shortint::ciphertext::CompactCiphertextList = &fhepk.encrypt_iter([clear_u64].iter().copied());
        let ct_1: &Vec<tfhe::shortint::Ciphertext> = &ct.expand(tfhe::shortint::parameters::ShortintCompactCiphertextListCastingMode::NoCasting).unwrap();
        let ct_2: &tfhe::shortint::Ciphertext = ct_1.get(0).unwrap();
        */

        let ct: tfhe::shortint::ciphertext::Ciphertext = expanded.get(0).unwrap().clone();
        return ct;
    }

    pub fn decrypt_by_private_key(&self, ct: &tfhe::shortint::ciphertext::Ciphertext) -> u64
//where 
    //    U: tfhe::integer::block_decomposition::RecomposableFrom<u64> + tfhe::core_crypto::prelude::UnsignedNumeric,
    {
        //option 1
        let pt: u64 = self.private_key.clone().unwrap().decrypt(&ct);

        //option 2
        //let c: &u128 = &fhesk.sk_int_radix.unwrap().decrypt(&z);

        return pt;
    }

    pub fn pts_int_to_cts_int(&self, nums: &Vec<u64>) -> tfhe::integer::RadixCiphertext {
        let mut bs: Vec<tfhe::shortint::Ciphertext> = Vec::new();
        for i in 0..nums.len() {
            bs.push(self.encrypt_by_public_key(nums[i]));
        }
        let cts = tfhe::integer::RadixCiphertext::from_blocks(bs);
        return cts;
    }

    pub fn cts_bits_to_ct_int(
        &self,
        cts_shortint: &Vec<tfhe::shortint::Ciphertext>,
    ) -> tfhe::integer::RadixCiphertext {
        let cts = tfhe::integer::RadixCiphertext::from_blocks(cts_shortint.to_vec());
        return cts;
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn get_zero_ct(&self, ct: tfhe::shortint::Ciphertext) -> tfhe::shortint::Ciphertext {
        // option 1
        //let t1 = mindsdk::util::now();
        let zero_ct = self.compute_key.as_ref().unwrap().unchecked_sub(&ct, &ct);

        // option 2
        // let t2 = mindsdk::util::now();
        //let zero1 = fheck.compute_key.as_ref().unwrap().unchecked_scalar_right_shift(&vector_of_cts[i][0], 8); // this will be slow;
        //let t3 = mindsdk::util::now();

        return zero_ct;
    }
}

/////////////////////////////////////////////////////////////////////////////////////////////////
pub fn private_key_convert_from_int_to_shortint(
    private_key_int: tfhe::integer::ClientKey,
) -> tfhe::shortint::ClientKey {
    let private_key_shortint: tfhe::shortint::ClientKey = private_key_int.into_raw_parts();
    return private_key_shortint;
}
pub fn compute_key_convert_from_int_to_shortint(
    compute_key_int: tfhe::integer::ServerKey,
) -> tfhe::shortint::ServerKey {
    let compute_key_shortint: tfhe::shortint::ServerKey = compute_key_int.as_ref().clone();
    return compute_key_shortint;
}
pub fn compute_key_compressed_convert_from_int_to_shortint(
    compute_key_int_compressed: tfhe::integer::CompressedServerKey,
) -> tfhe::shortint::CompressedServerKey {
    let compute_key_shortint_compressed: tfhe::shortint::CompressedServerKey =
        compute_key_int_compressed.into_raw_parts();
    return compute_key_shortint_compressed;
}
pub fn public_key_convert_from_int_to_shortint(
    public_key_int: tfhe::integer::CompactPublicKey,
) -> tfhe::shortint::CompactPublicKey {
    return public_key_compact_convert_from_int_to_shortint(public_key_int);
}
pub fn public_key_compact_convert_from_int_to_shortint(
    public_key_int_compact: tfhe::integer::CompactPublicKey,
) -> tfhe::shortint::CompactPublicKey {
    let public_key_shortint_compact: tfhe::shortint::CompactPublicKey =
        public_key_int_compact.into_raw_parts();
    return public_key_shortint_compact;
}
pub fn public_key_compressed_convert_from_int_to_shortint(
    public_key_int_compressed: tfhe::integer::CompressedPublicKey,
) -> tfhe::shortint::CompressedPublicKey {
    let public_key_shortint_compressed: tfhe::shortint::CompressedPublicKey =
        public_key_int_compressed.into_raw_parts();
    return public_key_shortint_compressed;
}
