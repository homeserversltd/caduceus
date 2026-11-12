/// Canonicalize the legacy HomeTV profile id at every profile read boundary.
pub(crate) fn canonical_profile_id(profile: &str) -> &str {
    if profile.eq_ignore_ascii_case("tv") {
        "hometv"
    } else {
        profile
    }
}
