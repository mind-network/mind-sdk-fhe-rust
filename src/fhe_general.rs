use tfhe::prelude::CiphertextList;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct FheGeneral {
    pub private_key: Option<tfhe::ClientKey>,
    pub compute_key: Option<tfhe::ServerKey>,
    pub public_key: Option<tfhe::CompactPublicKey>,
}

impl std::fmt::Debug for FheGeneral {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "FheGeneral {{ private_key: {}, compute_key: {}, public_key: {} }}",
            self.private_key.is_some(),
            self.compute_key.is_some(),
            self.public_key.is_some()
        )
    }
}

impl std::fmt::Display for FheGeneral {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "FheGeneral {{ private_key: {}, compute_key: {}, public_key: {} }}",
            self.private_key.is_some(),
            self.compute_key.is_some(),
            self.public_key.is_some()
        )
    }
}

impl Default for FheGeneral {
    fn default() -> Self {
        Self {
            private_key: None,
            compute_key: None,
            public_key: None,
        }
    }
}

impl FheGeneral {
    pub fn new() -> Self {
        Self {
            private_key: None,
            compute_key: None,
            public_key: None,
        }
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn new_from_private_key_local(fpath: &str) -> Self {
        //let private_key: tfhe::ClientKey = crate::io::read(fpath).unwrap();
        let private_key = crate::io::read(fpath);
        if private_key.is_none() {
            log::error!("fhekeyfile is wrong: {}, please check ...", fpath);
        }
        let private_key: tfhe::ClientKey = private_key.unwrap();

        let private_key = Some(private_key);
        Self {
            private_key: private_key,
            compute_key: None,
            public_key: None,
        }
    }
    pub fn new_from_compute_key_local(fpath: &str) -> Self {
        //let compute_key_compressed: tfhe::CompressedServerKey = crate::io::read(fpath).unwrap();
        let compute_key_compressed = crate::io::read(fpath);
        if compute_key_compressed.is_none() {
            log::error!("fhekeyfile is wrong: {}, please check ...", fpath);
        }
        let compute_key_compressed: tfhe::CompressedServerKey = compute_key_compressed.unwrap();
        let compute_key: tfhe::ServerKey = compute_key_compressed.decompress();
        let compute_key = Some(compute_key);
        Self {
            private_key: None,
            compute_key: compute_key,
            public_key: None,
        }
    }
    pub fn new_from_public_key_local(fpath: &str) -> Self {
        //println!("{:#}", fpath);
        //let public_key_compact = crate::io::read(fpath);
        //println!("{:#?}", public_key_compact);
        let public_key_compact = crate::io::read(fpath);
        if public_key_compact.is_none() {
            log::error!("fhekeyfile is wrong: {}, please check ...", fpath);
        }
        let public_key_compact: tfhe::CompactPublicKey = public_key_compact.unwrap();
        //let public_key_compact: tfhe::CompactPublicKey = public_key_compact.unwrap();
        let public_key = Some(public_key_compact);
        Self {
            private_key: None,
            compute_key: None,
            public_key: public_key,
        }
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn new_in_memory(&mut self) {
        self.private_key_generate();
        self.compute_key_load_memory();
        self.public_key_load_memory();
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn private_key_generate(&mut self) {
        let config = tfhe::ConfigBuilder::default().build();
        //println!("{:?}", config);
        let private_key: tfhe::ClientKey = tfhe::ClientKey::generate(config);
        self.private_key = Some(private_key);
    }
    pub fn private_key_save_local(&self, fpath: &str) {
        let _ = crate::io::write(self.private_key.as_ref().unwrap(), &fpath);
    }
    pub fn private_key_generate_save_local(&mut self, fpath: &str) {
        self.private_key_generate();
        self.private_key_save_local(fpath);
    }
    pub fn private_key_load_local(&mut self, fpath: &str) {
        let private_key: tfhe::ClientKey = crate::io::read(fpath).unwrap();
        let private_key = Some(private_key);
        self.private_key = private_key;
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn compute_key_compressed_generate(&mut self) -> tfhe::CompressedServerKey {
        let compute_key_compressed: tfhe::CompressedServerKey =
            tfhe::CompressedServerKey::new(&self.private_key.as_ref().unwrap());
        return compute_key_compressed;
    }
    pub fn compute_key_compressed_save_local(
        &self,
        compute_key_compressed: tfhe::CompressedServerKey,
        fpath: &str,
    ) {
        let _ = crate::io::write(compute_key_compressed, &fpath);
    }
    pub fn compute_key_compressed_generate_save_local(&mut self, fpath: &str) {
        let compute_key_compressed: tfhe::CompressedServerKey =
            self.compute_key_compressed_generate();
        self.compute_key_compressed_save_local(compute_key_compressed, fpath);
    }
    pub fn compute_key_generate_save_local(&mut self, fpath: &str) {
        self.compute_key_compressed_generate_save_local(fpath);
    }
    pub fn compute_key_load_local(&mut self, fpath: &str) {
        let compute_key_compressed: tfhe::CompressedServerKey = crate::io::read(fpath).unwrap();
        let compute_key: tfhe::ServerKey = compute_key_compressed.decompress();
        self.compute_key = Some(compute_key);
    }
    pub fn compute_key_load_memory(&mut self) {
        let compute_key_compressed = self.compute_key_compressed_generate();
        let compute_key: tfhe::ServerKey = compute_key_compressed.decompress();
        self.compute_key = Some(compute_key);
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn public_key_compact_generate(&mut self) -> tfhe::CompactPublicKey {
        let public_key_compact = tfhe::CompactPublicKey::new(&self.private_key.as_ref().unwrap());
        return public_key_compact;
    }
    pub fn public_key_compact_save_local(
        &self,
        public_key_compact: tfhe::CompactPublicKey,
        fpath: &str,
    ) {
        let _ = crate::io::write(public_key_compact, fpath);
    }
    pub fn public_key_compact_generate_save_local(&mut self, fpath: &str) {
        let public_key_compact = self.public_key_compact_generate();
        self.public_key_compact_save_local(public_key_compact, fpath);
    }
    pub fn public_key_compact_load_local(&mut self, fpath: &str) -> tfhe::CompactPublicKey {
        let public_key_compact: tfhe::CompactPublicKey = crate::io::read(fpath).unwrap();
        return public_key_compact;
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn public_key_compressed_generate(&mut self) -> tfhe::CompressedPublicKey {
        let public_key_compressed =
            tfhe::CompressedPublicKey::new(&self.private_key.as_ref().unwrap());
        return public_key_compressed;
    }
    pub fn public_key_compressed_save_local(
        &self,
        public_key_compressed: tfhe::CompressedPublicKey,
        fpath: &str,
    ) {
        let _ = crate::io::write(public_key_compressed, fpath);
    }
    pub fn public_key_compressed_generate_save_local(&mut self, fpath: &str) {
        let public_key_compressed = self.public_key_compressed_generate();
        self.public_key_compressed_save_local(public_key_compressed, fpath);
    }
    pub fn public_key_compressed_load_local(&mut self, fpath: &str) -> tfhe::CompressedPublicKey {
        let public_key_compressed: tfhe::CompressedPublicKey = crate::io::read(fpath).unwrap();
        return public_key_compressed;
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn public_key_generate_save_local(&mut self, fpath: &str) {
        self.public_key_compact_generate_save_local(fpath);
    }
    pub fn public_key_load_local(&mut self, fpath: &str) {
        let public_key: tfhe::CompactPublicKey = self.public_key_compact_load_local(fpath);
        self.public_key = Some(public_key);
    }
    pub fn public_key_load_memory(&mut self) {
        let public_key_compact = self.public_key_compact_generate();
        let public_key_compact = Some(public_key_compact);
        self.public_key = public_key_compact;
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn generate_keys_and_save_local_if_not_exist(&mut self, fpath: &str) {
        let fpath_fhesk = &format!("{}/fhesk.key", &fpath);
        if !std::path::Path::new(&fpath_fhesk).exists() {
            println!("not exist and to create fhe keys");
            let (_fp_private_key, _fp_compute_key, _fp_public_key) =
                self.generate_keys_and_save_local(fpath);
        } else {
            println!("key exist and skip generation");
        }
    }
    pub fn generate_keys_and_save_local(&mut self, fpath: &str) -> (String, String, String) {
        let fp_private_key = &format!("{}/fhesk.key", fpath);
        let fp_public_key = &format!("{}/fhepk.key", fpath);
        let fp_compute_key = &format!("{}/fheck.key", fpath);
        self.private_key_generate_save_local(fp_private_key);
        self.compute_key_compressed_generate_save_local(fp_compute_key);
        self.public_key_compact_generate_save_local(fp_public_key);
        return (
            fp_private_key.clone(),
            fp_compute_key.clone(),
            fp_public_key.clone(),
        );
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////

    pub fn encrypt_by_public_key<T, U>(&self, num: T) -> U
    where
        U: tfhe::integer::ciphertext::Expandable + tfhe::HlExpandable + tfhe::prelude::Tagged,
        T: tfhe::integer::ciphertext::Compactable,
    {
        let compact_list: tfhe::CompactCiphertextList =
            tfhe::CompactCiphertextList::builder(&self.public_key.as_ref().unwrap())
                .push(num)
                .build();
        let expanded: tfhe::CompactCiphertextListExpander = compact_list.expand().unwrap();
        let ct: U = expanded.get::<U>(0).unwrap().unwrap();
        return ct;
    }

    pub fn decrypt_by_private_key<T, U>(&self, ct: &T) -> U
    where
        T: tfhe::prelude::FheDecrypt<U>,
    {
        let pt: U = ct.decrypt(&self.private_key.as_ref().unwrap());
        return pt;
    }
}
