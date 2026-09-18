use std::collections::BTreeMap;

use secrecy::SecretString;
use serde_json::Value;

/// Turn the extracted secret value into a map of field -> secret.
///
/// A JSON object becomes one entry per key, a 1Password-style field array uses
/// each field's label/title/name/ID, and a scalar becomes a single `value`
/// entry.
pub(crate) fn secret_fields(value: &Value) -> BTreeMap<String, SecretString> {
    match value {
        Value::Object(map) => map
            .iter()
            .map(|(key, value)| (key.clone(), SecretString::from(scalar_to_string(value))))
            .collect(),
        Value::Array(items) => items.iter().filter_map(field_object_to_secret).collect(),
        other => BTreeMap::from([(
            "value".to_string(),
            SecretString::from(scalar_to_string(other)),
        )]),
    }
}

fn field_object_to_secret(value: &Value) -> Option<(String, SecretString)> {
    let object = value.as_object()?;
    let key = object
        .get("label")
        .or_else(|| object.get("title"))
        .or_else(|| object.get("name"))
        .or_else(|| object.get("id"))?
        .as_str()?;
    let value = object.get("value")?;
    Some((key.to_string(), SecretString::from(scalar_to_string(value))))
}

/// Render a JSON scalar as a plain string (no quotes); other shapes fall back
/// to their compact JSON form.
fn scalar_to_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        other => other.to_string(),
    }
}

/// Walk a dotted path (e.g. `data.data`) into a JSON value.
pub(crate) fn dot_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

#[cfg(test)]
// A failed unwrap in a test is the assertion failing, which is what a
// test is for; the workspace lint targets shipped code.
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

    #[test]
    fn secret_fields_maps_onepassword_field_arrays() {
        let fields = secret_fields(&serde_json::json!([
            {"id": "username", "label": "USERNAME", "value": "fake-user"},
            {"id": "password", "title": "PASSWORD", "value": "fake-password"},
            {"id": "empty"}
        ]));
        assert_eq!(fields.get("USERNAME").unwrap().expose_secret(), "fake-user");
        assert_eq!(
            fields.get("PASSWORD").unwrap().expose_secret(),
            "fake-password"
        );
        assert!(!fields.contains_key("empty"));
    }
}
