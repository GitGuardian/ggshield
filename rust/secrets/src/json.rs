use std::collections::BTreeMap;

use secrecy::SecretString;
use serde_json::Value;

/// A JSON object becomes one entry per key; anything else a single `value` entry.
pub(crate) fn secret_fields(value: &Value) -> BTreeMap<String, SecretString> {
    match value {
        Value::Object(map) => map
            .iter()
            .map(|(key, value)| (key.clone(), SecretString::from(scalar_to_string(value))))
            .collect(),
        other => BTreeMap::from([(
            "value".to_string(),
            SecretString::from(scalar_to_string(other)),
        )]),
    }
}

fn scalar_to_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        other => other.to_string(),
    }
}

pub(crate) fn dot_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

#[cfg(test)]
// A failed unwrap in a test is the assertion failing.
#[allow(clippy::unwrap_used)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn dot_path_walks_nested_objects() {
        let body: Value = serde_json::json!({"data": {"data": {"K": "V"}}});
        assert_eq!(
            dot_path(&body, "data.data").unwrap(),
            &serde_json::json!({"K": "V"})
        );
        assert!(dot_path(&body, "data.missing").is_none());
    }

    #[test]
    fn secret_fields_splits_objects_and_wraps_scalars() {
        let object = secret_fields(&serde_json::json!({"A": "1", "B": 2}));
        assert_eq!(object.get("A").unwrap().expose_secret(), "1");
        assert_eq!(object.get("B").unwrap().expose_secret(), "2");

        let scalar = secret_fields(&serde_json::json!("flat"));
        assert_eq!(scalar.get("value").unwrap().expose_secret(), "flat");
    }
}
