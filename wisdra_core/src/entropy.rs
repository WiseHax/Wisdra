//! Shannon Entropy Calculation Engine

/// Calculates the Shannon Entropy of a given byte slice.
/// Returns a value between 0.0 and 8.0, where higher values indicate
/// increased randomness (compression or encryption).
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequencies = [0usize; 256];
    for &byte in data {
        frequencies[byte as usize] += 1;
    }

    let mut entropy = 0.0;
    let data_len = data.len() as f64;

    for &count in &frequencies {
        if count > 0 {
            let probability = count as f64 / data_len;
            entropy -= probability * probability.log2();
        }
    }

    entropy
}

/// Evaluates the calculated entropy score against standard heuristic thresholds.
pub fn entropy_verdict(entropy: f64) -> &'static str {
    if entropy > 7.5 {
        "CRITICAL (Likely Packed/Encrypted)"
    } else if entropy > 7.0 {
        "HIGH (Obfuscated)"
    } else if entropy > 6.0 {
        "ELEVATED (Compressed Data)"
    } else if entropy > 4.0 {
        "NORMAL"
    } else {
        "LOW (Sparse Data)"
    }
}
