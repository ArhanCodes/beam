use rand::Rng;

const ADJECTIVES: &[&str] = &[
    "amber", "blue", "bold", "brave", "bright", "calm", "clean", "cool",
    "coral", "crisp", "dark", "dawn", "deep", "dual", "dusk", "fair",
    "fast", "fine", "firm", "fond", "free", "fresh", "glad", "gold",
    "good", "gray", "green", "hale", "keen", "kind", "late", "lean",
    "lime", "long", "loud", "mild", "mint", "near", "neat", "next",
    "nice", "nova", "open", "pale", "pine", "pink", "plum", "pure",
    "rare", "real", "red", "rich", "ripe", "rose", "ruby", "rust",
    "safe", "sage", "silk", "slim", "slow", "snow", "soft", "sure",
    "tall", "teal", "thin", "tiny", "true", "vast", "warm", "west",
    "wide", "wild", "wine", "wise", "zinc", "zone",
];

const NOUNS: &[&str] = &[
    "arch", "band", "bark", "barn", "bass", "beam", "bear", "bell",
    "bird", "boat", "bolt", "bone", "book", "cape", "cave", "chip",
    "clay", "cliff", "cloud", "coal", "coin", "core", "cove", "crow",
    "dawn", "deer", "dock", "dove", "drum", "dune", "dust", "edge",
    "fawn", "fern", "fire", "fish", "flag", "flint", "foam", "ford",
    "fork", "fort", "frog", "gate", "gaze", "glen", "glow", "gold",
    "gust", "hare", "hawk", "helm", "hill", "hive", "horn", "iron",
    "isle", "jade", "jazz", "keel", "kite", "knot", "lake", "lamp",
    "lark", "leaf", "lime", "lion", "loft", "lynx", "mare", "mars",
    "mesa", "mill", "mint", "mist", "moon", "moss", "nest", "north",
    "nova", "opal", "orca", "owl", "palm", "path", "peak", "pine",
    "pond", "port", "rain", "reef", "ring", "rock", "root", "rose",
    "rust", "sage", "sail", "sand", "seal", "seed", "snow", "star",
    "stem", "surf", "swan", "tarn", "tide", "toad", "tree", "vale",
    "veil", "vine", "wave", "wren", "wolf", "wood", "yard", "yew",
];

/// Generate a human-readable transfer code like "7-amber-wolf"
pub fn generate_code() -> String {
    let mut rng = rand::thread_rng();
    let num = rng.gen_range(1..100);
    let adj = ADJECTIVES[rng.gen_range(0..ADJECTIVES.len())];
    let noun = NOUNS[rng.gen_range(0..NOUNS.len())];
    format!("{}-{}-{}", num, adj, noun)
}

/// Convert a code string into bytes for use as a SPAKE2 password
pub fn code_to_bytes(code: &str) -> Vec<u8> {
    code.as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_code_format() {
        let code = generate_code();
        let parts: Vec<&str> = code.split('-').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts[0].parse::<u32>().is_ok());
    }
}
