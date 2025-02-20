use tfhe::integer::gen_keys_radix;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

fn main() {
    let mut ts = mind_sdk_fhe::util::TimeDuration::new();
    let mut tm = mind_sdk_fhe::util::TimeMessage::new();

    let num_block = 8;
    let (client_key, server_key) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_block);
    println!("new key is done");
    tm.insert("keys", ts.duration_and_reset());

    let msg1 = 10000u64;
    let msg2 = 1u64;
    let msg3 = 1u64;
    let scalar = 3u64;

    // message_modulus^vec_length
    let modulus = client_key
        .parameters()
        .message_modulus()
        .0
        .pow(num_block as u32) as u64;

    // We use the client key to encrypt two messages:
    let mut ct_1 = client_key.encrypt(msg1);
    let mut ct_2 = client_key.encrypt(msg2);
    let mut ct_3 = client_key.encrypt(msg3);
    tm.insert("encrypt", ts.duration_and_reset());

    server_key.smart_scalar_mul_assign(&mut ct_1, scalar);
    tm.insert("smart_scalar_mul_assign", ts.duration_and_reset());
    println!("smart_scalar_mul_assign");

    server_key.smart_add_assign(&mut ct_1, &mut ct_3);
    tm.insert("smart_add_assign", ts.duration_and_reset());
    println!("smart_add_assign");

    server_key.smart_sub_assign(&mut ct_1, &mut ct_2);
    tm.insert("smart_sub_assign", ts.duration_and_reset());
    println!("smart_sub_assign");

    for i in 0..10 {
        server_key.smart_sub_assign(&mut ct_1, &mut ct_2);
        println!("{:#?}", i);
    }
    tm.insert("smart_sub_assign_loop_x100", ts.duration_and_reset());

    // We use the client key to decrypt the output of the circuit:
    let output: u64 = client_key.decrypt(&ct_1);
    println!(
        "{:#?}, {:#?}, {:#?}",
        output,
        ((msg1 * scalar - msg2 - msg2 * 100) + msg3) % modulus,
        modulus
    );
    tm.insert("decrypt", ts.duration_and_reset());
    tm.pprint();
}
