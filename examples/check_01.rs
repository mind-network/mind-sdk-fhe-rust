fn more_ones_than_zeros(binary_array: &[u8]) -> &'static str {
    let mut balance = 0;

    for &bit in binary_array {
        balance ^= (bit << 1) | 1; // Adjust using bitwise logic
    }

    if balance & 1 != 0 {
        // Check the least significant bit
        "More 1s"
    } else if balance == 0 {
        "Equal"
    } else {
        "More 0s"
    }
}

fn main() {
    let binary_array = [1; 10000];
    let binary_array = [0; 10000];
    let binary_array = vec![1, 0, 1, 1, 0, 0];
    let result = more_ones_than_zeros(&binary_array);
    println!("Result: {}", result);
}
