use base64::Engine;
use std::io::{Read, Write};

pub fn mkdir(dir: &str) {
    std::fs::create_dir_all(dir).unwrap_or_else(|why| {
        println!("! {:?}", why.kind());
    });
}

pub fn touch(fpath: &str) -> Result<(), std::io::Error> {
    match std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(fpath)
    {
        Ok(_) => Ok(()),
        Err(e) => {
            println!("! {:?}", e.kind());
            return Err(e);
        }
    }
}

pub fn read<T>(path: &str) -> Option<T>
where
    T: serde::de::DeserializeOwned,
{
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return None,
    };

    let mut base64_string_read = String::new();
    if let Err(_) = file.read_to_string(&mut base64_string_read) {
        return None;
    }

    deserialize_base64::<T>(base64_string_read)
}

pub fn write<T: serde::Serialize>(
    content: T,
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let base64_string = serialize_base64(content).unwrap();
    let mut file = std::fs::File::create(path).expect("create file error");
    file.write_all(base64_string.as_bytes())
        .expect("write file error");
    Ok(())
}

pub fn serialize_base64<T: serde::Serialize>(
    content: T,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut serialized = vec![];
    bincode::serialize_into(&mut serialized, &content).expect("serialize error");
    Ok(base64::engine::general_purpose::STANDARD.encode(&serialized))
}

pub fn deserialize_base64<T: serde::de::DeserializeOwned>(base64_string: String) -> Option<T> {
    let key_code = match base64::engine::general_purpose::STANDARD.decode(base64_string) {
        Ok(decoded) => decoded,
        Err(_) => return None,
    };
    let mut serialized_data = std::io::Cursor::new(key_code);

    match bincode::deserialize_from(&mut serialized_data) {
        Ok(key) => Some(key),
        Err(e) => {
            println!("deserialize_error: {:#?}", e);
            None
        }
    }
}
