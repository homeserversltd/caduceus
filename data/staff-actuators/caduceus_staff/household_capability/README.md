# Household capability

This staff-only Python band maintains and signs short-lived household capability tokens. Public callers receive JSON tokens, status, and public-safe receipts; private signing material remains inside the staff actuator.

The ordered `skeleton-sha` child exposes only the SHA-256 identity digest of the fixed household skeleton key.
