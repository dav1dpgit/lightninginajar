//! LSAG linkable ring signature used for anonymous output registration.

use anyhow::{bail, Result};
use bitcoin::hashes::{sha256, Hash};
use secp::{MaybePoint, MaybeScalar, Point, Scalar};
use serde::{Deserialize, Serialize};

use crate::util::{derive_scalar, tagged_hash};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]   // LiJ P8
pub struct RingSig {
    pub key_image: String,
    pub c0: String,
    pub s: Vec<String>,
}

pub fn hash_to_point(p: &Point) -> Point {
    let bytes = p.serialize();
    for i in 0u32.. {
        let t = tagged_hash("joinstr/v2/hash_to_point", &[&bytes, &i.to_le_bytes()]);
        if let Ok(point) = Point::lift_x(t) {
            return point;
        }
    }
    unreachable!()
}

pub fn ring_hash(ring: &[Point]) -> [u8; 32] {
    let bytes: Vec<u8> = ring.iter().flat_map(|p| p.serialize()).collect();
    sha256::Hash::hash(&bytes).to_byte_array()
}

// ── LiJ P10: the same LSAG with a TAG (Tatara v0.9 §4.1; DP 2026-10-12 19:11 "weekly key image = ok") ──────────────────
// joinstr's key image x·Hp(P) is the same for every signature by one key, so every signature a key makes links to every
// other. With a tag, every member's Hp also takes the tag — Hp_t(P) = lift_x(H("joinstr/v2/lij/hash_to_point_tagged",
// P ‖ len(t) ‖ t ‖ i)) — so the image x·Hp_t(P) links two signatures only when they carry the same tag (the same week,
// in Tatara's seat requests), and the ring hash in every challenge is bound to the tag, so a signature made under one tag
// (or none) verifies under no other. The equations are joinstr's, with a different hash-to-point for each tag. joinstr's
// own untagged signatures are unchanged (its vectors still pass) — pools keep using them.

pub fn hash_to_point_tagged(p: &Point, tag: &[u8]) -> Point {
    let bytes = p.serialize();
    let len = (tag.len() as u32).to_le_bytes();
    for i in 0u32.. {
        let t = tagged_hash("joinstr/v2/lij/hash_to_point_tagged", &[&bytes, &len, tag, &i.to_le_bytes()]);
        if let Ok(point) = Point::lift_x(t) {
            return point;
        }
    }
    unreachable!()
}

fn ring_hash_tagged(ring: &[Point], tag: &[u8]) -> [u8; 32] {
    tagged_hash(
        "joinstr/v2/lij/ring_hash_tagged",
        &[&ring_hash(ring), &(tag.len() as u32).to_le_bytes(), tag],
    )
}

pub fn key_image_tagged(x: Scalar, tag: &[u8]) -> Point {
    x * hash_to_point_tagged(&x.base_point_mul(), tag)
}

/// Sign `m` under `tag` (LiJ P10). Same rules as `sign`.
pub fn sign_tagged(ring: &[Point], x: Scalar, m: &[u8; 32], aux: &[u8; 32], tag: &[u8]) -> Result<RingSig> {
    check_ring(ring)?;
    sign_core(ring, x, m, aux, &|p: &Point| hash_to_point_tagged(p, tag), ring_hash_tagged(ring, tag))
}

/// Verify a signature made under `tag` and return its key image (LiJ P10).
pub fn verify_tagged(ring: &[Point], m: &[u8; 32], sig: &RingSig, tag: &[u8]) -> Result<Point> {
    Ring::new_tagged(ring, tag)?.verify(m, sig)
}

fn challenge(rh: &[u8; 32], image: &Point, m: &[u8; 32], l: &Point, r: &Point) -> MaybeScalar {
    let h = tagged_hash(
        "joinstr/v2/ring",
        &[rh, &image.serialize(), m, &l.serialize(), &r.serialize()],
    );
    MaybeScalar::reduce_from(&h)
}

fn not_inf(p: MaybePoint) -> Result<Point> {
    match p.into_option() {
        Some(p) => Ok(p),
        None => bail!("point at infinity"),
    }
}

pub fn key_image(x: Scalar) -> Point {
    x * hash_to_point(&x.base_point_mul())
}

/// Sign `m` with `x`, whose public key must be in `ring` (sorted by bytes). LiJ P4: `aux` is 32 fresh random bytes from
/// the caller; the commitment and the decoy responses are derived from them together with the secret key, the message
/// and the ring, so a weak `aux` never repeats a commitment across messages.
pub fn sign(ring: &[Point], x: Scalar, m: &[u8; 32], aux: &[u8; 32]) -> Result<RingSig> {
    check_ring(ring)?;   // LiJ P7
    sign_core(ring, x, m, aux, &hash_to_point, ring_hash(ring))
}

/// The signing equations, shared by `sign` and `sign_tagged` (LiJ P10: only `hp` and the ring hash differ).
fn sign_core(
    ring: &[Point],
    x: Scalar,
    m: &[u8; 32],
    aux: &[u8; 32],
    hp: &dyn Fn(&Point) -> Point,
    rh: [u8; 32],
) -> Result<RingSig> {
    let n = ring.len();
    let pk = x.base_point_mul();
    let Some(j) = ring.iter().position(|p| *p == pk) else {
        bail!("own key not in ring");
    };
    let hp_j = hp(&pk);
    let image = x * hp_j;
    let xb = x.serialize();
    let a = derive_scalar("joinstr/v2/lij/ring-commit", &[aux, &xb, m, &rh]);
    let mut c = vec![MaybeScalar::Zero; n];
    let mut s = vec![MaybeScalar::Zero; n];
    c[(j + 1) % n] = challenge(&rh, &image, m, &a.base_point_mul(), &(a * hp_j));
    let mut i = (j + 1) % n;
    while i != j {
        s[i] = derive_scalar("joinstr/v2/lij/ring-decoy", &[aux, &xb, m, &rh, &(i as u32).to_le_bytes()]).into();
        let l = not_inf(s[i].base_point_mul() + c[i] * ring[i])?;
        let r = not_inf(s[i] * hp(&ring[i]) + c[i] * image)?;
        c[(i + 1) % n] = challenge(&rh, &image, m, &l, &r);
        i = (i + 1) % n;
    }
    s[j] = a - c[j] * x;
    Ok(RingSig {
        key_image: image.to_string(),
        c0: hex::encode(c[0].serialize()),
        s: s.iter().map(|v| hex::encode(v.serialize())).collect(),
    })
}

/// A ring with `Hp` of every member computed once, for verifying many signatures.
pub struct Ring {
    keys: Vec<Point>,
    hps: Vec<Point>,
    hash: [u8; 32],
}

/// LiJ P7: a ring is non-empty, sorted by its keys' bytes and without duplicates — the shape `ring_hash` assumes.
fn check_ring(keys: &[Point]) -> Result<()> {
    if keys.is_empty() {
        bail!("empty ring");
    }
    if !keys.windows(2).all(|w| w[0].serialize() < w[1].serialize()) {
        bail!("ring not sorted, or a key twice");
    }
    Ok(())
}

impl Ring {
    pub fn new(keys: &[Point]) -> Result<Self> {
        check_ring(keys)?;
        Ok(Ring {
            keys: keys.to_vec(),
            hps: keys.iter().map(hash_to_point).collect(),
            hash: ring_hash(keys),
        })
    }

    /// A ring for signatures made under `tag` (LiJ P10).
    pub fn new_tagged(keys: &[Point], tag: &[u8]) -> Result<Self> {
        check_ring(keys)?;
        Ok(Ring {
            keys: keys.to_vec(),
            hps: keys.iter().map(|p| hash_to_point_tagged(p, tag)).collect(),
            hash: ring_hash_tagged(keys, tag),
        })
    }

    /// Verify a ring signature and return its key image.
    pub fn verify(&self, m: &[u8; 32], sig: &RingSig) -> Result<Point> {
        verify_with(&self.keys, &self.hps, &self.hash, m, sig)
    }
}

/// Verify a ring signature and return its key image.
pub fn verify(ring: &[Point], m: &[u8; 32], sig: &RingSig) -> Result<Point> {
    Ring::new(ring)?.verify(m, sig)
}

fn verify_with(
    ring: &[Point],
    hps: &[Point],
    rh: &[u8; 32],
    m: &[u8; 32],
    sig: &RingSig,
) -> Result<Point> {
    if sig.s.len() != ring.len() || ring.is_empty() {
        bail!("ring size mismatch");
    }
    // LiJ P8: the key image a compressed point, every scalar exactly 32 bytes, all lowercase hex
    let image = crate::keys::point_from_hex(&sig.key_image)?;
    let scalar = |v: &str| -> Result<MaybeScalar> {
        Ok(MaybeScalar::from_slice(&crate::util::strict_hex(v, 32)?)?)
    };
    let c0 = scalar(&sig.c0)?;
    let s = sig.s.iter().map(|v| scalar(v)).collect::<Result<Vec<_>>>()?;
    let mut c = c0;
    for (i, p) in ring.iter().enumerate() {
        let l = not_inf(s[i].base_point_mul() + c * *p)?;
        let r = not_inf(s[i] * hps[i] + c * image)?;
        c = challenge(rh, &image, m, &l, &r);
    }
    if c != c0 {
        bail!("ring signature does not verify");
    }
    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::random_scalar;

    fn ring_of(n: usize) -> (Vec<Scalar>, Vec<Point>) {
        let mut xs: Vec<Scalar> = (0..n).map(|_| random_scalar()).collect();
        xs.sort_by_key(|x| x.base_point_mul().serialize());
        let ring = xs.iter().map(|x| x.base_point_mul()).collect();
        (xs, ring)
    }

    #[test]
    fn sign_and_verify_every_position() {
        let (xs, ring) = ring_of(5);
        let m = [7u8; 32];
        for x in &xs {
            let sig = sign(&ring, *x, &m, &crate::util::random_bytes()).unwrap();
            let image = verify(&ring, &m, &sig).unwrap();
            assert_eq!(image, key_image(*x));
        }
    }

    #[test]
    fn single_member_ring() {
        let (xs, ring) = ring_of(1);
        let sig = sign(&ring, xs[0], &[1u8; 32], &crate::util::random_bytes()).unwrap();
        verify(&ring, &[1u8; 32], &sig).unwrap();
    }

    #[test]
    fn key_image_links_two_signatures() {
        let (xs, ring) = ring_of(4);
        let a = verify(&ring, &[1u8; 32], &sign(&ring, xs[2], &[1u8; 32], &crate::util::random_bytes()).unwrap()).unwrap();
        let b = verify(&ring, &[2u8; 32], &sign(&ring, xs[2], &[2u8; 32], &crate::util::random_bytes()).unwrap()).unwrap();
        let c = verify(&ring, &[2u8; 32], &sign(&ring, xs[1], &[2u8; 32], &crate::util::random_bytes()).unwrap()).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn rejects_tampering() {
        let (xs, ring) = ring_of(3);
        let m = [9u8; 32];
        let sig = sign(&ring, xs[0], &m, &crate::util::random_bytes()).unwrap();
        assert!(verify(&ring, &[8u8; 32], &sig).is_err());
        let mut bad = sig.clone();
        bad.s[1] = hex::encode(random_scalar().serialize());
        assert!(verify(&ring, &m, &bad).is_err());
        let (_, other) = ring_of(3);
        assert!(verify(&other, &m, &sig).is_err());
        let outsider = random_scalar();
        assert!(sign(&ring, outsider, &m, &crate::util::random_bytes()).is_err());
    }

    #[test]
    fn hash_to_point_is_deterministic_with_even_y() {
        let (_, ring) = ring_of(4);
        for p in &ring {
            let h = hash_to_point(p);
            assert_eq!(h, hash_to_point(p));
            assert!(h.has_even_y());
            assert_ne!(h, *p);
        }
    }

    #[test]
    fn rejects_malformed_signatures() {
        let (xs, ring) = ring_of(3);
        let m = [5u8; 32];
        let sig = sign(&ring, xs[1], &m, &crate::util::random_bytes()).unwrap();
        verify(&ring, &m, &sig).unwrap();
        let order = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
        let mut bad = sig.clone();
        bad.s[0] = order.into();
        assert!(verify(&ring, &m, &bad).is_err());
        let mut bad = sig.clone();
        bad.c0 = order.into();
        assert!(verify(&ring, &m, &bad).is_err());
        let mut bad = sig.clone();
        bad.s.pop();
        assert!(verify(&ring, &m, &bad).is_err());
        let mut bad = sig.clone();
        bad.key_image = format!("05{}", "11".repeat(32));
        assert!(verify(&ring, &m, &bad).is_err());
        let mut bad = sig.clone();
        bad.key_image = key_image(xs[0]).to_string();
        assert!(verify(&ring, &m, &bad).is_err());
        assert!(verify(&[], &m, &sig).is_err());
    }
}
