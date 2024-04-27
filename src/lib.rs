mod utils;
mod error;
mod message;
mod record;
mod resolver;

pub use error::*;
pub use record::*;
pub use resolver::{query, Protocol};
