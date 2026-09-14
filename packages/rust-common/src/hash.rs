//! The one hash the hook uses: sha256, hex, lowercase. Same digest Python's
//! `hashlib.sha256(...).hexdigest()` produces, so the values are interchangeable
//! (ignore shas, content identifiers, cache keys).

use sha2::{Digest, Sha256};

pub fn sha256_hex(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    format!("{:x}", hasher.finalize())
}
