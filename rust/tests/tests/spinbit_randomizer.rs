use stealth::QuicFuscateStealth;

#[test]
fn spinbit_always_flips_when_probability_one() {
    let mut stealth = QuicFuscateStealth::new();
    stealth.spin.set_probability(1.0);
    assert!(!stealth.randomize_spinbit(true));
    assert!(stealth.randomize_spinbit(false));
}
