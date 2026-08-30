# Caduceus staff protocol seat

The repo-root schema.json is the sole protocol schema seat. build.rs reads this seat and emits typed metadata into OUT_DIR; index.rs includes that generated metadata while retaining the raw envelope so unknown top-level fields survive round trips.

The kernel fields and origin of intent are defined by the seat. Flags are presence-gated and represented generically without version comparison. Gate receipts append declared stamps while preserving raw fields.
