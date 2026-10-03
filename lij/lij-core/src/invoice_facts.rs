//! v303 (S54, DP 2026-10-02 10:11 "Fix all of these … Go."): what a BOLT11 invoice says — decoded and its signature
//! checked by lightning-invoice (Bolt11Invoice::from_str verifies the signature; the payee is the `n` field when the
//! invoice names one, else the key recovered from the signature) — so the page can check an invoice BEFORE paying it.
//! First user: the chit's funding invoice, which the wallet pays to its provider at mint — the page now pays it only
//! when its amount is the chit's and its payee is the provider (a provider that handed over a larger invoice, or one
//! to another node, is refused). Pure; no wallet state.

use std::str::FromStr;

use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct InvoiceFacts {
    /// the payee's node id, 33-byte compressed, hex
    pub payee: String,
    /// None = an amountless invoice
    pub amount_msat: Option<u64>,
    pub payment_hash: String,
    /// "bitcoin", "testnet", "signet", "regtest"
    pub network: String,
    /// unix seconds
    pub expires_at: u64,
}

pub fn invoice_facts(bolt11: &str) -> Result<InvoiceFacts, String> {
    let t = bolt11.trim();
    let t = if t.len() > 10 && t[..10].eq_ignore_ascii_case("lightning:") { &t[10..] } else { t };
    let inv = lightning_invoice::Bolt11Invoice::from_str(t).map_err(|e| format!("the invoice does not decode: {e}"))?;
    let payee = inv.payee_pub_key().copied().unwrap_or_else(|| inv.recover_payee_pub_key());
    Ok(InvoiceFacts {
        payee: hex::encode(payee.serialize()),
        amount_msat: inv.amount_milli_satoshis(),
        payment_hash: hex::encode(inv.payment_hash().as_ref() as &[u8]),
        network: inv.network().to_string(),
        expires_at: inv.duration_since_epoch().as_secs().saturating_add(inv.expiry_time().as_secs()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use lightning_invoice::{Currency, InvoiceBuilder};

    fn signed(amount_msat: Option<u64>, with_payee_field: bool) -> (String, PublicKey, [u8; 32]) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let preimage = [0x07u8; 32];
        let hash = sha256::Hash::hash(&preimage);
        let mut b = InvoiceBuilder::new(Currency::Bitcoin)
            .description("LIJOX allowance 1a2b3c4d".to_string())
            .duration_since_epoch(std::time::Duration::from_secs(1_790_000_000))
            .payment_hash(hash)
            .payment_secret(lightning::types::payment::PaymentSecret([0x11; 32]))
            .min_final_cltv_expiry_delta(144)
            .expiry_time(std::time::Duration::from_secs(900));
        if with_payee_field { b = b.payee_pub_key(pk); }
        let raw = match amount_msat { Some(a) => b.amount_milli_satoshis(a).build_raw(), None => b.build_raw() }.unwrap();
        let signed_raw = raw.sign::<_, ()>(|m| Ok(secp.sign_ecdsa_recoverable(m, &sk))).unwrap();
        let inv = lightning_invoice::Bolt11Invoice::from_signed(signed_raw).unwrap();
        (inv.to_string(), pk, hash.to_byte_array())
    }

    #[test]
    fn v303_reads_payee_amount_hash_and_expiry() {
        let (s, pk, hash) = signed(Some(5_000_000), false);
        let f = invoice_facts(&s).unwrap();
        assert_eq!(f.payee, hex::encode(pk.serialize()), "payee recovered from the signature");
        assert_eq!(f.amount_msat, Some(5_000_000));
        assert_eq!(f.payment_hash, hex::encode(hash));
        assert_eq!(f.network, "bitcoin");
        assert_eq!(f.expires_at, 1_790_000_900);
        // the explicit `n` field reads the same; the lightning: prefix and upper case are accepted
        let (s2, pk2, _) = signed(Some(5_000_000), true);
        assert_eq!(invoice_facts(&s2).unwrap().payee, hex::encode(pk2.serialize()));
        assert_eq!(invoice_facts(&format!("LIGHTNING:{}", s.to_uppercase())).unwrap(), f);
    }

    #[test]
    fn v303_amountless_and_refusals() {
        let (s, _, _) = signed(None, false);
        assert_eq!(invoice_facts(&s).unwrap().amount_msat, None);
        assert!(invoice_facts("lnbc1notaninvoice").is_err());
        assert!(invoice_facts("").is_err());
        // one character changed in the data part: the checksum (or the signature) no longer holds
        let (s, _, _) = signed(Some(1_000), false);
        let mut c: Vec<char> = s.chars().collect();
        let i = c.len() - 20;
        c[i] = if c[i] == 'q' { 'p' } else { 'q' };
        let tampered: String = c.into_iter().collect();
        assert!(invoice_facts(&tampered).is_err(), "a tampered invoice is refused");
    }
}
