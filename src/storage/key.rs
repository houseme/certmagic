//! Portable slash-delimited paths shared by filesystem and Redis storage.
use std::borrow::Cow;

use crate::error::{Error, Result, StorageError};

pub(super) fn canonical_path(key: &str, allow_root: bool) -> Result<Cow<'_, str>> {
    let mut canonical = true;
    let mut components = 0;
    for component in key.split('/') {
        if component.is_empty() || component == "." {
            canonical = false;
            continue;
        }
        if component == ".."
            || component.contains(['\0', '\\', ':'])
            || component.ends_with([' ', '.'])
        {
            return Err(Error::Storage(StorageError::InvalidKey(key.into())));
        }
        components += 1;
    }
    if components == 0 && !allow_root {
        return Err(Error::Storage(StorageError::InvalidKey(key.into())));
    }
    if canonical {
        return Ok(Cow::Borrowed(key));
    }
    let mut normalized = String::with_capacity(key.len());
    for component in key
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
    {
        if !normalized.is_empty() {
            normalized.push('/');
        }
        normalized.push_str(component);
    }
    Ok(Cow::Owned(normalized))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_identity_is_borrowed_and_aliases_are_idempotent() {
        assert!(matches!(
            canonical_path("dir/key", false).unwrap(),
            Cow::Borrowed(_)
        ));
        for alias in ["/dir/key/", "dir//key", "./dir/./key"] {
            let key = canonical_path(alias, false).unwrap();
            assert_eq!(key, "dir/key");
            assert_eq!(canonical_path(&key, false).unwrap(), key);
        }
        for invalid in [
            "", "/./", "../key", "dir/a:", "dir/a\\b", "dir/a.", "dir/a ", "dir/\0",
        ] {
            assert!(canonical_path(invalid, false).is_err(), "{invalid:?}");
        }
        assert_eq!(canonical_path("/./", true).unwrap(), "");
    }
}
