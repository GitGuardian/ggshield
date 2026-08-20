//! Take the version the hook reports in `GGShield-Version` and `User-Agent` from
//! ggshield's own `__version__`, so the two implementations cannot disagree about
//! it: a separate Cargo version here would report `0.1.0` on every native scan.

use std::path::Path;

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("rust/hook has a grandparent directory");
    let init = root.join("ggshield").join("__init__.py");

    // Fail the build rather than ship the wrong version: every build of this
    // crate happens inside the repository.
    let source = std::fs::read_to_string(&init)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", init.display()));
    let version = parse_version(&source)
        .unwrap_or_else(|| panic!("no __version__ = \"...\" in {}", init.display()));

    println!("cargo::rustc-env=GGSHIELD_VERSION={version}");
    println!("cargo::rerun-if-changed={}", init.display());
}

/// The `__version__ = "1.53.0"` assignment, single or double quoted.
fn parse_version(source: &str) -> Option<String> {
    source.lines().find_map(|line| {
        let value = line.strip_prefix("__version__")?.trim_start();
        let value = value.strip_prefix('=')?.trim();
        let quote = value.chars().next()?;
        if quote != '"' && quote != '\'' {
            return None;
        }
        let value = &value[1..];
        let end = value.find(quote)?;
        Some(value[..end].to_string())
    })
}
