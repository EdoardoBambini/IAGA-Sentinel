(module
  (memory (export "memory") 1)
  (global $heap (mut i32) (i32.const 4096))

  (data (i32.const 0) "review-hint")
  (data (i32.const 128) "0.4.0")
  (data (i32.const 256) "{\"riskScore\":55,\"findings\":[\"example plugin flagged outbound review\"],\"decisionHint\":\"review\"}")

  (func (export "alloc") (param $size i32) (result i32)
    global.get $heap
    global.get $heap
    local.get $size
    i32.add
    global.set $heap
  )

  (func (export "name") (result i32 i32)
    i32.const 0
    i32.const 11
  )

  (func (export "version") (result i32 i32)
    i32.const 128
    i32.const 5
  )

  (func (export "on_inspect") (param $ptr i32) (param $len i32) (result i32 i32)
    local.get $ptr
    drop
    local.get $len
    drop
    i32.const 256
    i32.const 94
  )
)
