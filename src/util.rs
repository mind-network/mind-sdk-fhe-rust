use itertools::Itertools;

pub struct TimeDuration {
    t: std::time::Instant,
}
impl Default for TimeDuration {
    fn default() -> Self {
        Self {
            t: std::time::Instant::now(),
        }
    }
}
impl TimeDuration {
    pub fn new() -> Self {
        Self {
            t: std::time::Instant::now(),
        }
    }
    pub fn now(&mut self) {
        self.reset();
    }
    pub fn reset(&mut self) {
        self.t = std::time::Instant::now();
    }
    pub fn duration(&self) -> std::time::Duration {
        return self.t.elapsed();
    }
    pub fn duration_and_reset(&mut self) -> std::time::Duration {
        let d = self.duration();
        self.reset();
        return d;
    }
}

pub struct TimeMessage {
    hm: Vec<(String, std::time::Duration)>,
}
impl Default for TimeMessage {
    fn default() -> Self {
        Self { hm: Vec::new() }
    }
}
impl TimeMessage {
    pub fn new() -> Self {
        Self { hm: Vec::new() }
    }
    pub fn insert(&mut self, key: &str, value: std::time::Duration) {
        self.hm.push((String::from(key), value));
    }
    pub fn pprint(&self) {
        for i in 0..self.hm.len() {
            println!("\t{} : {:?} : {}", i, self.hm[i].1, self.hm[i].0);
        }
    }
}

pub fn get_file_size(fpath: &str) -> size::Size {
    let x = std::fs::metadata(fpath);
    match x {
        Ok(x) => {
            let x = x.len();
            let x = size::Size::from_bytes(x);
            return x;
        }
        Err(e) => {
            println!("fpath: {:#?}", fpath);
            println!("get_file_size_error: {:#?}", e);
            return size::Size::from_bytes(0);
        }
    }
}

pub fn get_default_fpath() -> (&'static str, &'static str, &'static str) {
    let fpath_cts = "./data/cts";
    crate::io::mkdir(fpath_cts);
    let fpath_pts = "./data/pts";
    crate::io::mkdir(fpath_pts);
    let fpath_keys = "./data/keys";
    crate::io::mkdir(fpath_cts);
    return (fpath_keys, fpath_cts, fpath_pts);
}

pub fn bin_fmt_u8(num: u8) -> String {
    let s = format!("u8:{:#010b}", num);
    let bytes: Vec<_> = s.bytes().rev().collect();
    let chunks: Vec<_> = bytes
        .chunks(8)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();
    let result: Vec<_> = chunks.join("_").bytes().rev().collect();
    String::from_utf8(result).unwrap()
}

pub fn bin_fmt_u16(num: u16) -> String {
    let s = format!("u16:{:#018b}", num);
    let bytes: Vec<_> = s.bytes().rev().collect();
    let chunks: Vec<_> = bytes
        .chunks(8)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();
    let result: Vec<_> = chunks.join("_").bytes().rev().collect();
    String::from_utf8(result).unwrap()
}

pub fn bin_fmt_u32(num: u32) -> String {
    let s = format!("u32:{:#034b}", num);
    let bytes: Vec<_> = s.bytes().rev().collect();
    let chunks: Vec<_> = bytes
        .chunks(8)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();
    let result: Vec<_> = chunks.join("_").bytes().rev().collect();
    String::from_utf8(result).unwrap()
}

pub fn bin_fmt_u164(num: u64) -> String {
    let s = format!("u64:{:#066b}", num);
    let bytes: Vec<_> = s.bytes().rev().collect();
    let chunks: Vec<_> = bytes
        .chunks(8)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();
    let result: Vec<_> = chunks.join("_").bytes().rev().collect();
    String::from_utf8(result).unwrap()
}

pub fn bin_fmt_u128(num: u128) -> String {
    let s = format!("u128:{:#0130b}", num);
    let bytes: Vec<_> = s.bytes().rev().collect();
    let chunks: Vec<_> = bytes
        .chunks(8)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();
    let result: Vec<_> = chunks.join("_").bytes().rev().collect();
    String::from_utf8(result).unwrap()
}

pub fn bin_fmt_u128_2(s: String) -> String {
    let mut result = String::with_capacity(s.len() + ((s.len() - 1) / 3));
    let mut i = s.len();
    for c in s.chars() {
        result.push(c);
        i -= 1;
        if i > 0 && i % 3 == 0 {
            result.push(' ');
        }
    }
    result
}

pub fn pprint_hm_u128(hm: std::collections::HashMap<usize, Vec<u128>>, modulus: u128) {
    for i in hm.keys().sorted() {
        let mut t = 0 as u128;
        for v in hm[i].clone() {
            //println!("{}", v);
            t += v as u128;
        }
        println!(
            "ID {} {}: \t {:?} \t=> sum:{} mod:{} \t\tbin:{} ",
            i,
            std::any::type_name_of_val(&hm[i][0]),
            hm[i],
            t,
            t % (modulus as u128),
            bin_fmt_u128(t as u128)
        ); // for debug
    }
}
