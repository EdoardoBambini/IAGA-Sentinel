#![no_main]
use libfuzzer_sys::fuzz_target;

use std::collections::HashSet;
use iaga_sentinel::modules::session_graph::session_dag;

fuzz_target!(|data: &[u8]| {
    let len = data.len();
    if len < 4 {
        return;
    }

    // Use first byte to determine number of calls (1-8)
    let num_calls = ((data[0] % 8) + 1) as usize;
    let rest = &data[1..];

    let session_id = format!("fuzz-session-{:x}", u32::from_le_bytes([
        rest.first().copied().unwrap_or(0),
        rest.get(1).copied().unwrap_or(0),
        rest.get(2).copied().unwrap_or(0),
        rest.get(3).copied().unwrap_or(0),
    ]));

    let action_types = ["file_read", "file_write", "shell", "http", "db_query", "email", "custom"];
    let tools = ["bash", "curl", "psql", "filesystem.read", "http.fetch"];

    for i in 0..num_calls {
        let byte = rest.get(4 + i).copied().unwrap_or(0);
        let action = action_types[(byte as usize) % action_types.len()];
        let tool = tools[((byte >> 3) as usize) % tools.len()];

        let result = session_dag::add_tool_call_to_session(
            &session_id,
            "fuzz-agent",
            tool,
            action,
            HashSet::new(),
        );

        // Invariant: anomaly score in [0, 100]
        assert!(result.anomaly_score <= 100);
    }
});
