#![no_main]
use libfuzzer_sys::fuzz_target;

use std::collections::HashSet;
use iaga_sentinel::modules::taint::taint_tracker;

fuzz_target!(|data: &[u8]| {
    // Split fuzz input into 3 parts for the 3 string parameters
    let len = data.len();
    if len < 3 {
        return;
    }
    let split1 = len / 3;
    let split2 = 2 * len / 3;

    let action_type = match std::str::from_utf8(&data[..split1]) {
        Ok(s) => s,
        Err(_) => return,
    };
    let tool_name = match std::str::from_utf8(&data[split1..split2]) {
        Ok(s) => s,
        Err(_) => return,
    };
    let payload_str = match std::str::from_utf8(&data[split2..]) {
        Ok(s) => s,
        Err(_) => return,
    };

    let inherited = HashSet::new();
    let result = taint_tracker::analyze_taint(action_type, tool_name, payload_str, &inherited);

    // Invariant: accumulated labels are a superset of inherited
    for label in &inherited {
        assert!(result.accumulated_labels.contains(label));
    }
});
