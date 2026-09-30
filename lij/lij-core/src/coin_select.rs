//! v281 (S50, coin control — DP's pick rule, 2026-09-28): ONE coin-picking rule for
//! plain sends and self-funded channel opens.
//!
//!   1. The smallest single coin that covers the target on its own (target = the
//!      amount plus the fee a one-input transaction pays).
//!   2. Only when no single coin is enough: largest first, until covered.
//!
//! Frozen coins never reach this function — the callers filter them out first.
//! Deterministic: equal values fall back to the caller's order (index). The rule was
//! "largest first, always" (S15 → v280); a small payment then dragged the wallet's
//! biggest coin into every transaction.

/// Pick coins for a target. `values[i]` is the i-th candidate's value in sats;
/// `need(n)` is the total a transaction with `n` inputs must carry (amount + the fee
/// for `n` inputs). Returns the chosen indexes into `values` (in pick order), or `None`
/// when every coin together is still short.
pub fn pick(values: &[u64], need: impl Fn(usize) -> u64) -> Option<Vec<usize>> {
    if values.is_empty() {
        return None;
    }
    // 1. Smallest single coin that covers the one-input target.
    let one = need(1);
    let mut asc: Vec<usize> = (0..values.len()).collect();
    asc.sort_by(|&a, &b| values[a].cmp(&values[b]).then(a.cmp(&b)));
    if let Some(&i) = asc.iter().find(|&&i| values[i] >= one) {
        return Some(vec![i]);
    }
    // 2. Largest first until covered.
    let mut desc: Vec<usize> = (0..values.len()).collect();
    desc.sort_by(|&a, &b| values[b].cmp(&values[a]).then(a.cmp(&b)));
    let mut chosen: Vec<usize> = Vec::new();
    let mut total: u64 = 0;
    for i in desc {
        chosen.push(i);
        total = total.saturating_add(values[i]);
        if total >= need(chosen.len()) {
            return Some(chosen);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::pick;

    // amount + 100 sats per input, the shape estimate_fee_with gives.
    fn need_for(amount: u64) -> impl Fn(usize) -> u64 {
        move |n| amount + 100 * n as u64
    }

    #[test]
    fn smallest_single_coin_that_covers_wins() {
        // 5,000 covers 3,000 + 100; 2,000 does not; 50,000 would but is not the smallest.
        let v = [50_000, 2_000, 5_000, 8_000];
        assert_eq!(pick(&v, need_for(3_000)), Some(vec![2]));
    }

    #[test]
    fn exact_fit_counts_as_covering() {
        let v = [3_100, 9_000];
        assert_eq!(pick(&v, need_for(3_000)), Some(vec![0]));
    }

    #[test]
    fn no_single_coin_enough_then_largest_first() {
        // Need 12,000 + fee. No coin alone; largest first: 8,000 + 5,000 = 13,000 ≥ 12,200.
        let v = [2_000, 5_000, 8_000, 1_000];
        assert_eq!(pick(&v, need_for(12_000)), Some(vec![2, 1]));
    }

    #[test]
    fn fee_grows_with_inputs_and_is_honoured() {
        // 8,000 + 5,000 = 13,000: covers 12,700 + 200 = 12,900; a third coin not needed.
        let v = [8_000, 5_000, 2_000];
        assert_eq!(pick(&v, need_for(12_700)), Some(vec![0, 1]));
        // 12,900 + 200 = 13,100 > 13,000 → the third coin joins (13,000 + 2,000 ≥ 12,900 + 300).
        assert_eq!(pick(&v, need_for(12_900)), Some(vec![0, 1, 2]));
    }

    #[test]
    fn short_returns_none() {
        let v = [1_000, 2_000];
        assert_eq!(pick(&v, need_for(5_000)), None);
        assert_eq!(pick(&[], need_for(1)), None);
    }

    #[test]
    fn ties_are_deterministic_by_index() {
        let v = [5_000, 5_000, 5_000];
        assert_eq!(pick(&v, need_for(3_000)), Some(vec![0]));
        // Largest-first over equal coins keeps index order too.
        assert_eq!(pick(&v, need_for(9_000)), Some(vec![0, 1]));
    }
}
