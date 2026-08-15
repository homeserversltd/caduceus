# Caduceus staff protocol seat

index.json is the sole protocol schema seat. build.rs reads this root seat and emits typed metadata into OUT_DIR; index.rs includes that generated metadata while retaining the raw envelope so unknown top-level fields survive round trips.

The kernel fields and target default are defined only by the seat. Flags are presence-gated and represented generically, without invented family names or version comparison. Gate receipts append declared stamps while preserving raw fields.
