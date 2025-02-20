pub use crate::FheGeneral;
pub use std::option::Option;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct FheInt {
    pub private_key: Option<tfhe::integer::ClientKey>,
    pub compute_key: Option<tfhe::integer::ServerKey>,
    pub public_key: Option<tfhe::integer::CompactPublicKey>,
}

impl std::fmt::Debug for FheInt {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "FheInt {{ private_key: {}, compute_key: {}, public_key: {} }}",
            self.private_key.is_some(),
            self.compute_key.is_some(),
            self.public_key.is_some()
        )
    }
}

impl std::fmt::Display for FheInt {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "FheInt {{ private_key: {}, compute_key: {}, public_key: {} }}",
            self.private_key.is_some(),
            self.compute_key.is_some(),
            self.public_key.is_some()
        )
    }
}

impl Default for FheInt {
    fn default() -> Self {
        Self {
            private_key: None,
            compute_key: None,
            public_key: None,
        }
    }
}

impl From<FheGeneral> for FheInt {
    fn from(item: FheGeneral) -> Self {
        let mut private_key: Option<tfhe::integer::ClientKey> = None;
        let mut compute_key: Option<tfhe::integer::ServerKey> = None;
        let mut public_key: Option<tfhe::integer::CompactPublicKey> = None;
        if item.private_key.is_some() {
            private_key = Some(private_key_convert_from_general_to_int(
                item.private_key.unwrap(),
            ));
        }
        if item.compute_key.is_some() {
            compute_key = Some(compute_key_convert_from_general_to_int(
                item.compute_key.unwrap(),
            ));
        }
        if item.public_key.is_some() {
            public_key = Some(public_key_convert_from_general_to_int(
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

impl FheInt {
    pub fn new() -> Self {
        Self {
            private_key: None,
            compute_key: None,
            public_key: None,
        }
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn new_from_private_key_local(fpath: &str) -> Self {
        let private_key = crate::io::read(fpath);
        if private_key.is_none() {
            log::error!("fhekeyfile is wrong: {}, please check ...", fpath);
        }
        let private_key: tfhe::integer::ClientKey = private_key.unwrap();

        let private_key = Some(private_key);
        Self {
            private_key: private_key,
            compute_key: None,
            public_key: None,
        }
    }
    pub fn new_from_compute_key_local(fpath: &str) -> Self {
        let compute_key_int_compressed = crate::io::read(fpath);
        if compute_key_int_compressed.is_none() {
            log::error!("fhekeyfile is wrong: {}, please check ...", fpath);
        }
        let compute_key_int_compressed: tfhe::integer::CompressedServerKey =
            compute_key_int_compressed.unwrap();

        let compute_key: tfhe::integer::ServerKey = compute_key_int_compressed.decompress();
        let compute_key = Some(compute_key);
        Self {
            private_key: None,
            compute_key: compute_key,
            public_key: None,
        }
    }
    pub fn new_from_public_key_local(fpath: &str) -> Self {
        let public_key_int_compact = crate::io::read(fpath);
        if public_key_int_compact.is_none() {
            log::error!("fhekeyfile is wrong: {}, please check ...", fpath);
        }
        let public_key_int_compact: tfhe::integer::CompactPublicKey =
            public_key_int_compact.unwrap();

        let public_key = Some(public_key_int_compact);
        Self {
            private_key: None,
            compute_key: None,
            public_key: public_key,
        }
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn new_from_private_key_general_local(fpath: &str) -> Self {
        let private_key_general = crate::io::read(fpath);
        if private_key_general.is_none() {
            log::error!("fhekeyfile is wrong: {}, please check ...", fpath);
        }
        let private_key_general: tfhe::ClientKey = private_key_general.unwrap();
        let private_key_int: tfhe::integer::ClientKey =
            private_key_convert_from_general_to_int(private_key_general);
        let private_key = Some(private_key_int);
        Self {
            private_key: private_key,
            compute_key: None,
            public_key: None,
        }
    }
    pub fn new_from_compute_key_general_local(fpath: &str) -> Self {
        let compute_key_general_compressed: tfhe::CompressedServerKey =
            crate::io::read(fpath).unwrap();
        let compute_key_general: tfhe::ServerKey = compute_key_general_compressed.decompress();
        let compute_key_int: tfhe::integer::ServerKey =
            compute_key_convert_from_general_to_int(compute_key_general);
        let compute_key = Some(compute_key_int);
        Self {
            private_key: None,
            compute_key: compute_key,
            public_key: None,
        }
    }
    pub fn new_from_public_key_general_local(fpath: &str) -> Self {
        let public_key_general: tfhe::CompactPublicKey = crate::io::read(fpath).unwrap();
        let public_key_int: tfhe::integer::CompactPublicKey =
            public_key_convert_from_general_to_int(public_key_general);
        let public_key = Some(public_key_int);
        Self {
            private_key: None,
            compute_key: None,
            public_key: public_key,
        }
    }
    pub fn private_key_load_local_and_convert_from_general(
        &mut self,
        fpath: &str,
    ) -> tfhe::integer::ClientKey {
        let private_key_general: tfhe::ClientKey = crate::io::read(fpath).unwrap();
        let private_key_int: tfhe::integer::ClientKey =
            private_key_convert_from_general_to_int(private_key_general);
        return private_key_int;
    }
    pub fn private_key_save_local(&self, fpath: &str) {
        let _ = crate::io::write(self.private_key.clone().unwrap(), &fpath);
    }
    pub fn private_key_load_local(&mut self, fpath: &str) {
        let private_key: tfhe::integer::ClientKey = crate::io::read(fpath).unwrap();
        let private_key = Some(private_key);
        self.private_key = private_key;
    }
    pub fn get_private_key_int_radix(&self, num_bits: usize) -> tfhe::integer::RadixClientKey {
        return private_key_convert_from_int_into_int_radix(
            self.private_key.clone().unwrap(),
            num_bits,
        );
    }
    pub fn private_key_int_radix_save_local(&self, fpath: &str, num_bits: usize) {
        let private_key_int_radix = self.get_private_key_int_radix(num_bits);
        let _ = crate::io::write(private_key_int_radix, &fpath);
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn compute_key_compressed_load_local_and_convert_from_general(
        &mut self,
        fpath: &str,
    ) -> tfhe::integer::CompressedServerKey {
        let compute_key_compressed: tfhe::CompressedServerKey = crate::io::read(fpath).unwrap();
        let compute_key_int_compressed: tfhe::integer::CompressedServerKey =
            compute_key_compressed_convert_from_general_to_int(compute_key_compressed);
        return compute_key_int_compressed;
    }
    pub fn compute_key_compressed_save_local(
        &self,
        compute_key_int_compressed: tfhe::integer::CompressedServerKey,
        fpath: &str,
    ) {
        let _ = crate::io::write(compute_key_int_compressed, &fpath);
    }
    pub fn compute_key_compressed_load_local(&mut self, fpath: &str) {
        let compute_key_int_compressed: tfhe::integer::CompressedServerKey =
            crate::io::read(fpath).unwrap();
        let compute_key: tfhe::integer::ServerKey = compute_key_int_compressed.decompress();
        self.compute_key = Some(compute_key);
    }
    pub fn compute_key_load_local(&mut self, fpath: &str) {
        self.compute_key_compressed_load_local(fpath);
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn public_key_compressed_load_local_and_convert_from_general(
        &mut self,
        fpath: &str,
    ) -> tfhe::integer::CompressedPublicKey {
        let public_key_compressed: tfhe::CompressedPublicKey = crate::io::read(fpath).unwrap();
        let public_key_int_compressed: tfhe::integer::CompressedPublicKey =
            public_key_compressed_convert_from_general_to_int(public_key_compressed);
        return public_key_int_compressed;
    }
    pub fn public_key_compressed_save_local(
        &self,
        public_key_int_compressed: tfhe::integer::CompressedPublicKey,
        fpath: &str,
    ) {
        let _ = crate::io::write(public_key_int_compressed, &fpath);
    }
    pub fn public_key_compressed_load_local(&mut self, fpath: &str) -> tfhe::integer::PublicKey {
        let public_key_int_compressed: tfhe::integer::CompressedPublicKey =
            crate::io::read(fpath).unwrap();
        let public_key_int_compressed: tfhe::integer::PublicKey =
            public_key_int_compressed.decompress();
        //self.ck = Some(ck);
        return public_key_int_compressed;
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn public_key_compact_load_local_and_convert_from_general(
        &mut self,
        fpath: &str,
    ) -> tfhe::integer::CompactPublicKey {
        let public_key_compact: tfhe::CompactPublicKey = crate::io::read(fpath).unwrap();
        let public_key_int_compact: tfhe::integer::CompactPublicKey =
            public_key_compact_convert_from_general_to_int(public_key_compact);
        return public_key_int_compact;
    }
    pub fn public_key_compact_save_local(
        &self,
        public_key_int_compact: tfhe::integer::CompactPublicKey,
        fpath: &str,
    ) {
        let _ = crate::io::write(public_key_int_compact, &fpath);
    }
    pub fn public_key_compact_load_local(
        &mut self,
        fpath: &str,
    ) -> tfhe::integer::CompactPublicKey {
        let public_key_int_compact: tfhe::integer::CompactPublicKey =
            crate::io::read(fpath).unwrap();
        //self.compute_key = Some(compute_key);
        return public_key_int_compact;
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn public_key_load_local(&mut self, fpath: &str) {
        let public_key_int = self.public_key_compact_load_local(fpath);
        let public_key_int = Some(public_key_int);
        self.public_key = public_key_int;
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn generate_keys_and_save_local_if_not_exist(&mut self, fpath: &str) {
        let fpath_fhesk = &format!("{}/fhesk_int.key", &fpath);
        if !std::path::Path::new(&fpath_fhesk).exists() {
            println!("not exist and to create fhe keys");
            let private_key_int = self
                .private_key_load_local_and_convert_from_general(&format!("{}/fhesk.key", fpath));
            let _ = crate::io::write(private_key_int, &format!("{}/fhesk_int.key", fpath));

            let compute_key_int = self.compute_key_compressed_load_local_and_convert_from_general(
                &format!("{}/fheck.key", fpath),
            );
            let _ = crate::io::write(compute_key_int, &format!("{}/fheck_int.key", fpath));

            let public_key_int = self.public_key_compact_load_local_and_convert_from_general(
                &format!("{}/fhepk.key", fpath),
            );
            let _ = crate::io::write(public_key_int, &format!("{}/fhepk_int.key", fpath));
        } else {
            println!("key exist and skip generation");
        }
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn encrypt_by_public_key_debug<T>(&self, num: T) -> tfhe::integer::RadixCiphertext
    // not in use
    where
        T: tfhe::integer::ciphertext::Compactable,
        //U: tfhe::integer::ciphertext::Expandable,
    {
        // option 1
        let compact_list: tfhe::integer::ciphertext::CompactCiphertextList =
            tfhe::integer::ciphertext::CompactCiphertextList::builder(
                &self.public_key.as_ref().unwrap(),
            )
            .push(num)
            .build();
        let expanded: tfhe::integer::ciphertext::CompactCiphertextListExpander = compact_list
            .expand(
                tfhe::integer::ciphertext::IntegerCompactCiphertextListExpansionMode::NoCastingAndNoUnpacking
                //::NoUnpacking,tfhe::integer::ciphertext::IntegerCompactCiphertextListExpansionMode::NoCasting,
            )
            .unwrap();

        // option 2
        //let x: tfhe::integer::RadixCiphertext = fhepk.public_key_int.clone().unwrap().encrypt_radix_compact(34028236692093846346337460743176821145 as u128, 64).expand(
        //    tfhe::integer::ciphertext::IntegerCompactCiphertextListUnpackingMode::NoUnpacking,
        //    tfhe::integer::ciphertext::IntegerCompactCiphertextListCastingMode::NoCasting,
        //).unwrap().get(0).unwrap().unwrap();

        let ct: tfhe::integer::RadixCiphertext = expanded
            .get::<tfhe::integer::RadixCiphertext>(0)
            .unwrap()
            .unwrap();
        return ct;
    }

    pub fn encrypt_by_public_key<T>(&self, num: T) -> tfhe::integer::RadixCiphertext
    where
        //T: tfhe::integer::ciphertext::Compactable + tfhe::core_crypto::prelude::Numeric,
        T: tfhe::integer::block_decomposition::DecomposableInto<u64>
            + std::ops::Shl<usize, Output = T>, //U: tfhe::integer::ciphertext::Expandable,
    {
        // std::any::TypeID::of::<T>() == std::any::TypeID::of::<u8>() // not try
        let t_type = std::any::type_name_of_val(&num);
        //println!("Data type to encrypt: {}", t_type);
        match t_type {
            "u8" => return self.encrypt_by_public_key_radix(num, 4),
            "u16" => return self.encrypt_by_public_key_radix(num, 8), // update for changes
            "u32" => return self.encrypt_by_public_key_radix(num, 16),
            "u64" => return self.encrypt_by_public_key_radix(num, 32),
            "u128" => return self.encrypt_by_public_key_radix(num, 64),
            _ => panic!("Data type for FHE encryption must be on of [u8, u16, u32, u64]"),
        }
    }

    pub fn encrypt_by_public_key_radix<T>(
        &self,
        num: T,
        num_blocks_per_integer: usize,
    ) -> tfhe::integer::RadixCiphertext
    where
        //T: tfhe::integer::ciphertext::Compactable + tfhe::core_crypto::prelude::Numeric,
        T: tfhe::integer::block_decomposition::DecomposableInto<u64>
            + std::ops::Shl<usize, Output = T>, //U: tfhe::integer::ciphertext::Expandable,
    {
        let compact_list: tfhe::integer::ciphertext::CompactCiphertextList = self
            .public_key
            .as_ref()
            .unwrap()
            .encrypt_radix_compact(num, num_blocks_per_integer);
        let expanded: tfhe::integer::ciphertext::CompactCiphertextListExpander = compact_list
            .expand(
                tfhe::integer::ciphertext::IntegerCompactCiphertextListExpansionMode::NoCastingAndNoUnpacking
                //tfhe::integer::ciphertext::IntegerCompactCiphertextListUnpackingMode::NoUnpacking, // or UnpackIfNecessary
                //tfhe::integer::ciphertext::IntegerCompactCiphertextListCastingMode::NoCasting, // CastIfNecessary
            )
            .unwrap();

        let ct: tfhe::integer::RadixCiphertext = expanded
            .get::<tfhe::integer::RadixCiphertext>(0)
            .unwrap()
            .unwrap();
        return ct;
    }

    pub fn encrypt_by_public_key_build<T>(&self, num: T) -> tfhe::integer::RadixCiphertext
    // not in use right now
    where
        T: tfhe::integer::ciphertext::Compactable + tfhe::core_crypto::prelude::Numeric,
        //U: tfhe::integer::ciphertext::Expandable,
    {
        // encrypt 8-bit integers (signed or unsigned) by using 4 shortint blocks that store 2 bits of message each.
        // for PARAM_MESSAGE_2_CARRY_2_KS_PBS
        let num_blocks = 4;

        // option 1
        let mut clb: tfhe::integer::ciphertext::CompactCiphertextListBuilder =
            tfhe::integer::ciphertext::CompactCiphertextList::builder(
                &self.public_key.as_ref().unwrap(),
            );
        let compact_list: tfhe::integer::ciphertext::CompactCiphertextList =
            clb.push_with_num_blocks(num, num_blocks).build(); // the blocksize is defined by the key size.
                                                               //let compact_list:tfhe::integer::ciphertext::CompactCiphertextList = clb.push_with_num_blocks(num, num_blocks).build_packed(); // the blocksize is defined by the key size.
        let expanded: tfhe::integer::ciphertext::CompactCiphertextListExpander = compact_list
            .expand(
                tfhe::integer::ciphertext::IntegerCompactCiphertextListExpansionMode::NoCastingAndNoUnpacking
                //tfhe::integer::ciphertext::IntegerCompactCiphertextListUnpackingMode::NoUnpacking, // or UnpackIfNecessary
                //tfhe::integer::ciphertext::IntegerCompactCiphertextListCastingMode::NoCasting, // CastIfNecessary
            )
            .unwrap();

        // option 2
        //let x: tfhe::integer::RadixCiphertext = fhepk.public_key_int.clone().unwrap().encrypt_radix_compact(34028236692093846346337460743176821145 as u128, 64).expand(
        //    tfhe::integer::ciphertext::IntegerCompactCiphertextListUnpackingMode::NoUnpacking,
        //    tfhe::integer::ciphertext::IntegerCompactCiphertextListCastingMode::NoCasting,
        //).unwrap().get(0).unwrap().unwrap();

        let ct: tfhe::integer::RadixCiphertext = expanded
            .get::<tfhe::integer::RadixCiphertext>(0)
            .unwrap()
            .unwrap();
        return ct;
    }

    pub fn decrypt_by_private_key<U>(&self, ct: &tfhe::integer::RadixCiphertext) -> U
    where
        U: tfhe::integer::block_decomposition::RecomposableFrom<u64>
            + tfhe::core_crypto::prelude::UnsignedNumeric,
    {
        //option 1
        let pt: U = self.private_key.clone().unwrap().decrypt_radix(&ct);

        //option 2
        //let c: &u128 = &fhesk.private_key_int_radix.unwrap().decrypt(&z);

        return pt;
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn get_zero_ct(
        &self,
        ct: tfhe::integer::RadixCiphertext,
    ) -> tfhe::integer::RadixCiphertext {
        // option 1
        //let t1 = mindsdk::util::now();
        let zero_ct = self.compute_key.as_ref().unwrap().unchecked_sub(&ct, &ct);

        // option 2
        // let t2 = mindsdk::util::now();
        //let zero1 = fheck.ck.as_ref().unwrap().unchecked_scalar_right_shift(&vector_of_cts[i][0], 8); // this will be slow;
        //let t3 = mindsdk::util::now();

        return zero_ct;
    }

    pub fn trim_radix_blocks_lsb(
        &self,
        ct: &tfhe::integer::RadixCiphertext,
        num_block: usize,
    ) -> tfhe::integer::RadixCiphertext {
        // 119u64, 4 => 2 => 7
        return self
            .compute_key
            .as_ref()
            .unwrap()
            .trim_radix_blocks_lsb(ct, num_block);
    }
    pub fn trim_radix_blocks_msb(
        &self,
        ct: &tfhe::integer::RadixCiphertext,
        num_block: usize,
    ) -> tfhe::integer::RadixCiphertext {
        // 119u64, 4 => 2 => 7
        return self
            .compute_key
            .as_ref()
            .unwrap()
            .trim_radix_blocks_msb(ct, num_block);
    }
}

/////////////////////////////////////////////////////////////////////////////////////////////////
pub fn private_key_convert_from_general_to_int(
    private_key_general: tfhe::ClientKey,
) -> tfhe::integer::ClientKey {
    let private_key_int: tfhe::integer::ClientKey = private_key_general.as_ref().clone();
    return private_key_int;
}

pub fn private_key_convert_from_int_into_int_radix(
    private_key_int: tfhe::integer::ClientKey,
    num_bits: usize,
) -> tfhe::integer::RadixClientKey {
    let private_key_int_radix: tfhe::integer::RadixClientKey =
        tfhe::integer::RadixClientKey::from((private_key_int, num_bits));
    return private_key_int_radix;
}

pub fn compute_key_compressed_convert_from_general_to_int(
    ck_compressed_general: tfhe::CompressedServerKey,
) -> tfhe::integer::CompressedServerKey {
    let (ck_int_compressed, _, _, _, _): (tfhe::integer::CompressedServerKey, _, _, _, _) =
        ck_compressed_general.into_raw_parts();
    return ck_int_compressed;
}

pub fn compute_key_convert_from_general_to_int(
    ck_general: tfhe::ServerKey,
) -> tfhe::integer::ServerKey {
    let ck_int: tfhe::integer::ServerKey = ck_general.as_ref().clone();
    return ck_int;
}

pub fn public_key_convert_from_general_to_int(
    public_key_general: tfhe::CompactPublicKey,
) -> tfhe::integer::CompactPublicKey {
    public_key_compact_convert_from_general_to_int(public_key_general)
}

pub fn public_key_compact_convert_from_general_to_int(
    public_key_general: tfhe::CompactPublicKey,
) -> tfhe::integer::CompactPublicKey {
    let (public_key_int, _): (tfhe::integer::CompactPublicKey, _) =
        public_key_general.into_raw_parts();
    return public_key_int;
}

pub fn public_key_compressed_convert_from_general_to_int(
    public_key_compressed_general: tfhe::CompressedPublicKey,
) -> tfhe::integer::CompressedPublicKey {
    let (ck_int_compressed, _): (tfhe::integer::CompressedPublicKey, _) =
        public_key_compressed_general.into_raw_parts();
    return ck_int_compressed;
}

pub fn radix_num_blocks_to_represent_unsigned_value() {}
