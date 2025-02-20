use futures::future::join_all;
use tfhe::prelude::*;
use tfhe::{
    generate_keys, set_server_key, ConfigBuilder, FheInt16, FheInt2, FheInt4, FheInt8, FheUint8,
};

#[tokio::main]
async fn main() {
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();

    let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    set_server_key(server_key);

    //let clears = [-1i16, 2, 3, 4, -5];
    let clearss = [[1 as u8; 255]; 32];
    let clearss: Vec<Vec<u8>> = clearss.iter().map(|row| row.to_vec()).collect();

    let mut chunk_id = 0;
    let chunk_size = 32;
    for chunk in clearss.chunks(chunk_size as usize) {
        let tasks: Vec<_> = chunk
            .iter()
            .map(|clears| run_once(chunk_id, clears, &client_key)) // Ensure `event` is cloneable
            .collect();
        let results: Vec<FheUint8> = join_all(tasks).await;
        let result: FheUint8 = results.iter().sum::<FheUint8>();
        let decrypted: u16 = result.decrypt(&client_key);
        println!("chunk_id: {:#?}, decrypted: {:#?}", chunk_id, decrypted);

        chunk_id += 1;
        tm.insert(
            &format!("sum_chueck_id_{:#?}", chunk_id),
            ts.duration_and_reset(),
        );
    }

    // Iter and sum on references
    tm.insert("finish all decrypt", ts.duration_and_reset());
    tm.pprint();

    // 100 items, FheInt8 = 105s
    // 100 items, FheUint8 = 100s
}

async fn run_once(chunk_id: i32, clears: &Vec<u8>, client_key: &tfhe::ClientKey) -> FheUint8 {
    println!("chuck_id: {:#?}, {:?}", chunk_id, clears);
    let encrypted = do_encrypt(clears, client_key).await;
    let result = do_sum_in_subgroup(encrypted).await;
    return result;
}

async fn do_sum_in_subgroup(encrypted: Vec<FheUint8>) -> FheUint8 {
    let result: FheUint8 = encrypted.iter().sum::<FheUint8>();
    return result;
}

async fn do_encrypt(clears: &Vec<u8>, client_key: &tfhe::ClientKey) -> Vec<FheUint8> {
    let encrypted: Vec<FheUint8> = clears
        .iter()
        .copied()
        .map(|x| FheUint8::encrypt(x, client_key))
        .collect::<Vec<_>>();
    return encrypted;
}
