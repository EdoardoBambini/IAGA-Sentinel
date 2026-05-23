#![no_main]
use libfuzzer_sys::fuzz_target;

use iaga_sentinel::modules::injection_firewall::prompt_firewall;

fuzz_target!(|data: &str| {
    let result = prompt_firewall::scan_prompt(data);

    // Invariant: score in [0, 100]
    assert!(result.risk_score <= 100);
    // Invariant: blocked iff score >= 75
    assert_eq!(result.blocked, result.risk_score >= 75);
    // Invariant: at least 2 stages always run
    assert!(result.stages_run >= 2);
});
