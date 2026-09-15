use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;

use super::Http;
use crate::error::SecretError;
use crate::json::secret_fields;

struct Target {
    params: BTreeMap<String, String>,
    item_exists: bool,
}

impl Http {
    pub(super) fn get_onepassword_secrets(
        &self,
        path: &str,
    ) -> Result<BTreeMap<String, SecretString>> {
        let target = self.onepassword_target(path, false)?;
        let item = self.fetch_value("read_secret", &target.params)?;
        let fields = item
            .get("fields")
            .context("1Password item response did not contain a fields array")?;
        Ok(secret_fields(fields))
    }

    pub(super) fn set_onepassword_secrets(
        &self,
        path: &str,
        updates: &BTreeMap<String, SecretString>,
    ) -> Result<()> {
        let target = self.onepassword_target(path, true)?;
        if target.item_exists {
            let mut item = self.fetch_value("read_secret", &target.params)?;
            merge_item_fields(&mut item, updates)?;
            self.send_json("write_secret", &target.params, &item)
        } else {
            let body = serde_json::json!({
                "vault": {"id": target.params["vault_id"]},
                "title": target.params["item"],
                "category": "SECURE_NOTE",
                "fields": item_fields(updates),
            });
            self.send_json("create_secret", &target.params, &body)
        }
    }

    pub(super) fn delete_onepassword_secrets(&self, path: &str, keys: &[String]) -> Result<()> {
        let target = self.onepassword_target(path, false)?;
        if keys.is_empty() {
            return self.send_empty("delete_secret", &target.params);
        }

        let mut item = self.fetch_value("read_secret", &target.params)?;
        remove_item_fields(&mut item, keys)?;
        let is_empty = item
            .get("fields")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty);
        if is_empty {
            self.send_empty("delete_secret", &target.params)
        } else {
            self.send_json("write_secret", &target.params, &item)
        }
    }

    fn onepassword_target(&self, path: &str, allow_missing_item: bool) -> Result<Target> {
        let (vault, item) = parse_path(path)?;
        let mut params = BTreeMap::from([
            ("vault".to_string(), vault.to_string()),
            ("item".to_string(), item.to_string()),
        ]);

        let vaults = self.fetch_value("list_vaults", &params)?;
        let vault_id = resolve_id(&vaults, "vault", vault, "name", path)?
            .context("1Password vault unexpectedly missing")?;
        params.insert("vault_id".to_string(), vault_id);

        let items = self.fetch_value("list_items", &params)?;
        let item_id = resolve_id(&items, "item", item, "title", path)?;
        match item_id {
            Some(item_id) => {
                params.insert("item_id".to_string(), item_id);
                Ok(Target {
                    params,
                    item_exists: true,
                })
            }
            None if allow_missing_item => Ok(Target {
                params,
                item_exists: false,
            }),
            None => Err(SecretError::SecretNotFound {
                path: path.to_string(),
            }
            .into()),
        }
    }
}

fn parse_path(path: &str) -> Result<(&str, &str)> {
    let Some((vault, item)) = path.split_once('/') else {
        bail!("path '{path}' must be '<vault>/<item>', e.g. dev/myapp");
    };
    if vault.is_empty() || item.is_empty() || item.contains('/') {
        bail!("path '{path}' must be '<vault>/<item>', e.g. dev/myapp");
    }
    Ok((vault, item))
}

fn resolve_id(
    values: &Value,
    kind: &str,
    query: &str,
    name_key: &str,
    path: &str,
) -> Result<Option<String>> {
    let matches = values
        .as_array()
        .context("1Password Connect list response was not an array")?
        .iter()
        .filter_map(|value| {
            let object = value.as_object()?;
            let id = object.get("id")?.as_str()?;
            let name = object.get(name_key).and_then(Value::as_str);
            (id == query || name == Some(query))
                .then(|| (id.to_string(), name.map(str::to_string).unwrap_or_default()))
        })
        .collect::<Vec<_>>();

    match matches.as_slice() {
        [] if kind == "vault" => Err(SecretError::SecretNotFound {
            path: path.to_string(),
        }
        .into()),
        [] => Ok(None),
        [(id, _)] => Ok(Some(id.clone())),
        _ => {
            let ids = matches
                .iter()
                .map(|(id, name)| {
                    if name.is_empty() {
                        id.clone()
                    } else {
                        format!("{name} ({id})")
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            bail!("more than one 1Password {kind} matches '{query}'; specify its ID: {ids}")
        }
    }
}

fn item_fields(fields: &BTreeMap<String, SecretString>) -> Vec<Value> {
    fields
        .iter()
        .map(|(key, value)| {
            serde_json::json!({
                "label": key,
                "type": "CONCEALED",
                "value": value.expose_secret(),
            })
        })
        .collect()
}

fn merge_item_fields(item: &mut Value, updates: &BTreeMap<String, SecretString>) -> Result<()> {
    let fields = item
        .get_mut("fields")
        .and_then(Value::as_array_mut)
        .context("1Password item response did not contain a fields array")?;
    for (key, value) in updates {
        if let Some(field) = fields
            .iter_mut()
            .find(|field| field_matches_key(field, key))
        {
            field["value"] = Value::String(value.expose_secret().to_string());
        } else {
            fields.push(serde_json::json!({
                "label": key,
                "type": "CONCEALED",
                "value": value.expose_secret(),
            }));
        }
    }
    Ok(())
}

fn remove_item_fields(item: &mut Value, keys: &[String]) -> Result<()> {
    let fields = item
        .get_mut("fields")
        .and_then(Value::as_array_mut)
        .context("1Password item response did not contain a fields array")?;
    let missing = keys
        .iter()
        .filter(|key| !fields.iter().any(|field| field_matches_key(field, key)))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(SecretError::missing_fields(&missing).into());
    }
    fields.retain(|field| !keys.iter().any(|key| field_matches_key(field, key)));
    Ok(())
}

fn field_matches_key(field: &Value, key: &str) -> bool {
    field.get("label").and_then(Value::as_str) == Some(key)
        || field.get("title").and_then(Value::as_str) == Some(key)
        || field.get("id").and_then(Value::as_str) == Some(key)
}

#[cfg(test)]
// A failed unwrap in a test is the assertion failing, which is what a
// test is for; the workspace lint targets shipped code.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn path_requires_exactly_a_vault_and_item() {
        assert_eq!(parse_path("dev/myapp").unwrap(), ("dev", "myapp"));
        assert!(parse_path("dev").is_err());
        assert!(parse_path("dev/team/myapp").is_err());
    }

    #[test]
    fn resolves_names_and_ids() {
        let values = serde_json::json!([
            {"id": "first-id", "name": "dev"},
            {"id": "second-id", "name": "prod"}
        ]);
        assert_eq!(
            resolve_id(&values, "vault", "dev", "name", "dev/myapp").unwrap(),
            Some("first-id".to_string())
        );
        assert_eq!(
            resolve_id(&values, "vault", "second-id", "name", "prod/myapp").unwrap(),
            Some("second-id".to_string())
        );
    }

    #[test]
    fn updates_and_removes_item_fields() {
        let mut item = serde_json::json!({
            "fields": [
                {"id": "api", "label": "API_KEY", "type": "CONCEALED", "value": "old"}
            ]
        });
        merge_item_fields(
            &mut item,
            &BTreeMap::from([
                ("API_KEY".to_string(), SecretString::from("new".to_string())),
                (
                    "DB_URL".to_string(),
                    SecretString::from("fake://db".to_string()),
                ),
            ]),
        )
        .unwrap();
        assert_eq!(item["fields"].as_array().unwrap().len(), 2);
        assert_eq!(item["fields"][0]["value"], "new");

        remove_item_fields(&mut item, &["API_KEY".to_string()]).unwrap();
        assert_eq!(item["fields"].as_array().unwrap().len(), 1);
        assert_eq!(item["fields"][0]["label"], "DB_URL");
    }
}
