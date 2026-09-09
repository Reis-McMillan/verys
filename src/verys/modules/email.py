def normalize_email(value):
    """Canonical form used for storage and lookups: stripped, lower-cased."""
    if isinstance(value, str):
        return value.strip().lower()
    return value
