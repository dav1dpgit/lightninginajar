use bitcoin::hashes::{sha256, Hash, HashEngine};

/// BIP340 tagged hash over the concatenation of `parts`.
pub fn tagged_hash(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let t = sha256::Hash::hash(tag.as_bytes());
    let mut e = sha256::Hash::engine();
    e.input(t.as_ref());
    e.input(t.as_ref());
    for p in parts {
        e.input(p);
    }
    sha256::Hash::from_engine(e).to_byte_array()
}

// LiJ P4/P5 (docs/joinstr-patches.md): no randomness, clock or display helpers in the library — every random byte comes
// from the caller (the engine's source, the one the 12 words come from). A secret scalar is derived from the caller's
// bytes, hedged with the secret and the message, by `derive_scalar`.

/// A non-zero scalar below the curve order from a tagged hash of `parts` (LiJ P4). The counter makes the (2^-128-rare)
/// out-of-range case total, never a panic.
pub fn derive_scalar(tag: &str, parts: &[&[u8]]) -> secp::Scalar {
    let mut ctr: u32 = 0;
    loop {
        let c = ctr.to_le_bytes();
        let mut all: Vec<&[u8]> = parts.to_vec();
        all.push(&c);
        if let Ok(s) = secp::Scalar::from_slice(&tagged_hash(tag, &all)) {
            return s;
        }
        ctr = ctr.wrapping_add(1);
    }
}

/// LiJ P8: hex from a peer is lowercase, exactly `bytes` long — nothing else is decoded.
pub fn strict_hex(s: &str, bytes: usize) -> anyhow::Result<Vec<u8>> {
    if s.len() != 2 * bytes || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        anyhow::bail!("expected {bytes} bytes of lowercase hex");
    }
    Ok(hex::decode(s)?)
}

/// LiJ P8: like `strict_hex` for a length within `min..=max` bytes (a DER signature).
pub fn strict_hex_range(s: &str, min: usize, max: usize) -> anyhow::Result<Vec<u8>> {
    if s.len() % 2 != 0 || s.len() < 2 * min || s.len() > 2 * max {
        anyhow::bail!("expected {min} to {max} bytes of lowercase hex");
    }
    strict_hex(s, s.len() / 2)
}

#[cfg(test)]
pub fn random_bytes() -> [u8; 32] {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

#[cfg(test)]
pub fn random_scalar() -> secp::Scalar {
    loop {
        if let Ok(s) = secp::Scalar::from_slice(&random_bytes()) {
            return s;
        }
    }
}
