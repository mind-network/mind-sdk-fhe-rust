#![doc(html_no_source)]

pub mod fhe_client;
pub mod fhe_general;
pub mod fhe_int;
pub mod fhe_shortint;
pub mod io;
pub mod util;

pub use crate::fhe_client::*;
pub use crate::fhe_general::*;
pub use crate::fhe_int::*;
pub use crate::fhe_shortint::*;

#[derive(Debug, Clone)]
pub enum FheKeyType {
    FhePrivateKey,
    FhePublicKey,
    FheComputeKey,
}
