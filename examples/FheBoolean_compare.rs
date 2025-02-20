use tfhe::boolean::prelude::*;

fn main() {
    // We generate a set of client/server keys, using the default parameters:
    let (client_key, server_key) = gen_keys();

    let bool1 = true;
    let bool2 = false;
    let bool3 = true;

    // We use the client secret key to encrypt a message:
    let ct_1 = client_key.encrypt(bool1);
    let ct_2 = client_key.encrypt(bool2);
    let ct_3 = client_key.encrypt(bool3);

    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();
    // We use the server public key to execute the NOT gate:
    let ct_xor = server_key.mux(&ct_1, &ct_2, &ct_3);
    tm.insert("mux", ts.duration_and_reset());

    // We use the client key to decrypt the output of the circuit:
    let output = client_key.decrypt(&ct_xor);
    println!("{:#?}, {:#?}", output, if bool1 { bool2 } else { bool3 });
    tm.insert("decrypt", ts.duration_and_reset());
    tm.pprint();
}
