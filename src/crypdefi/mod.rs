/// Possible errors
pub mod error;
mod http;
/// Bot usage tool
pub mod user;

pub use http::Signature;
pub use http::SignatureRequestKind;
