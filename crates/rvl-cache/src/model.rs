//! The decision model's bundle: fetched, verified and cached like the spec
//! cache.
//!
//! `GET /api/v1/scanner/model` (org key) answers
//! `{"manifest": <raw JSON>, "signature": "<base64 ed25519>"}`. The signature
//! covers the manifest's exact bytes, so they are kept as received and never
//! re-encoded, and it verifies against the same pinned keyset as the spec
//! cache. The manifest names each file of the bundle with its sha256; a file
//! is fetched from `bundle_url + sha256`, relative to the API base, and kept
//! only when its bytes hash to that digest.
//!
//! On disk, under `<cache>/model/`:
//!
//! ```text
//! current/manifest.json      the manifest bytes as signed
//! current/manifest.json.sig  the detached signature
//! current/<name>             each file the manifest lists
//! ```
//!
//! A new bundle is staged in `incoming/` and swapped in whole, so a scan sees
//! the old bundle or the new one, never a mix. [`ModelStore::load`] verifies
//! the signature and every file's digest again, so a cached bundle that was
//! changed on disk is refused, not run.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::value::RawValue;

use crate::{sha256_hex, Keyset};

/// The store's directory under the spec-cache root.
pub const MODEL_DIR: &str = "model";

/// The one manifest schema this binary reads.
pub const SUPPORTED_MODEL_SCHEMA: u32 = 1;

/// The tokenizer file every bundle carries.
pub const TOKENIZER_FILE: &str = "tokenizer.json";

const MANIFEST: &str = "manifest.json";
const SIG: &str = "manifest.json.sig";

/// The published manifest. Unknown fields are ignored: the publisher may add
/// one without a schema bump.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ModelManifest {
    pub schema_version: u32,
    pub model_id: String,
    #[serde(default)]
    pub weights_sha256: String,
    /// The input layout the model was trained on: `compact` or `full`.
    pub layout: String,
    /// Tokens per input.
    pub max_len: usize,
    /// Calibration temperature.
    pub temperature: f64,
    /// The controls the model passed its publication gate for: the only ones
    /// it decides.
    #[serde(default)]
    pub served_controls: Vec<ControlEntry>,
    /// The controls it did not pass the gate for.
    #[serde(default)]
    pub withheld_controls: Vec<ControlEntry>,
    /// Where files are fetched from: `bundle_url + sha256`, relative to the
    /// API base.
    pub bundle_url: String,
    pub files: Vec<BundleFile>,
    #[serde(default)]
    pub published_at: String,
}

/// A control the manifest lists, with the measurements it was gated on.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(from = "RawControl")]
pub struct ControlEntry {
    pub control: String,
    pub precision: Option<f64>,
    pub ece: Option<f64>,
}

/// A listed control: an object, or the bare control code.
#[derive(Deserialize)]
#[serde(untagged)]
enum RawControl {
    Code(String),
    Entry {
        control: String,
        #[serde(default)]
        precision: Option<f64>,
        #[serde(default)]
        ece: Option<f64>,
    },
}

impl From<RawControl> for ControlEntry {
    fn from(r: RawControl) -> Self {
        match r {
            RawControl::Code(control) => ControlEntry {
                control,
                precision: None,
                ece: None,
            },
            RawControl::Entry {
                control,
                precision,
                ece,
            } => ControlEntry {
                control,
                precision,
                ece,
            },
        }
    }
}

/// One file of the bundle.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct BundleFile {
    pub name: String,
    /// Lower-case hex.
    pub sha256: String,
    #[serde(default)]
    pub size: u64,
}

impl ModelManifest {
    /// Parse manifest bytes: the schema first, so a newer manifest is named
    /// as such rather than as malformed.
    pub fn parse(bytes: &[u8]) -> anyhow::Result<ModelManifest> {
        #[derive(Deserialize)]
        struct Schema {
            schema_version: u32,
        }
        let s: Schema = serde_json::from_slice(bytes)?;
        anyhow::ensure!(
            s.schema_version == SUPPORTED_MODEL_SCHEMA,
            "model manifest schema_version {} is not supported (this binary reads {}); \
             upgrade rvl",
            s.schema_version,
            SUPPORTED_MODEL_SCHEMA
        );
        let m: ModelManifest = serde_json::from_slice(bytes)?;
        m.check()?;
        Ok(m)
    }

    /// The file that holds the model: the one `.onnx` file.
    pub fn model_file(&self) -> &BundleFile {
        // `check` guarantees exactly one.
        self.files
            .iter()
            .find(|f| f.name.ends_with(".onnx"))
            .expect("checked manifest has one .onnx file")
    }

    /// Whether the model decides `control`.
    pub fn serves(&self, control: &str) -> bool {
        self.served_controls.iter().any(|c| c.control == control)
    }

    fn check(&self) -> anyhow::Result<()> {
        anyhow::ensure!(!self.model_id.trim().is_empty(), "model_id is empty");
        anyhow::ensure!(
            self.bundle_url.starts_with('/') && !self.bundle_url.starts_with("//"),
            "bundle_url {:?} is not a path on the API",
            self.bundle_url
        );
        let mut seen = std::collections::BTreeSet::new();
        for f in &self.files {
            let plain = !f.name.is_empty()
                && !f.name.starts_with('.')
                && f.name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c));
            anyhow::ensure!(
                plain && f.name != MANIFEST && f.name != SIG,
                "file name {:?} is not a plain file name",
                f.name
            );
            anyhow::ensure!(seen.insert(&f.name), "file {:?} is listed twice", f.name);
            anyhow::ensure!(
                f.sha256.len() == 64
                    && f.sha256
                        .chars()
                        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
                "file {:?} has no sha256",
                f.name
            );
        }
        let onnx = self
            .files
            .iter()
            .filter(|f| f.name.ends_with(".onnx"))
            .count();
        anyhow::ensure!(onnx == 1, "the bundle lists {onnx} .onnx files, not 1");
        anyhow::ensure!(
            seen.contains(&TOKENIZER_FILE.to_string()),
            "the bundle lists no {TOKENIZER_FILE}"
        );
        Ok(())
    }
}

/// A verified bundle on disk.
#[derive(Debug)]
pub struct CachedModel {
    /// Holds every file the manifest lists, under its name.
    pub dir: PathBuf,
    pub manifest: ModelManifest,
}

/// What the manifest endpoint returned.
pub enum FetchedModel {
    New {
        manifest: Vec<u8>,
        sig_b64: String,
    },
    /// HTTP 404: no model is published at `url`.
    NotPublished {
        url: String,
    },
}

/// Transport: HTTP in production, in-memory in tests.
pub trait ModelFetcher {
    fn manifest(&self) -> anyhow::Result<FetchedModel>;
    /// The bytes at `path`, relative to the API base.
    fn blob(&self, path: &str) -> anyhow::Result<Vec<u8>>;
}

/// The outcome of a model sync. A sync never fails a scan.
#[derive(Debug, PartialEq, Eq)]
pub enum ModelSyncOutcome {
    /// RVL_OFFLINE=1: no fetch attempted.
    Offline,
    /// The published manifest is the cached one.
    UpToDate {
        model_id: String,
    },
    Installed {
        model_id: String,
    },
    /// A bad signature, a malformed manifest or a file whose digest is not
    /// the listed one. Nothing was installed.
    Rejected {
        reason: String,
    },
    FetchFailed {
        reason: String,
    },
    NotPublished {
        url: String,
    },
    InstallFailed {
        reason: String,
    },
}

impl ModelSyncOutcome {
    /// One line for `rvl model sync`.
    pub fn message(&self) -> String {
        match self {
            ModelSyncOutcome::Offline => "offline (RVL_OFFLINE=1): no fetch attempted".into(),
            ModelSyncOutcome::UpToDate { model_id } => {
                format!("decision model {model_id} is up to date")
            }
            ModelSyncOutcome::Installed { model_id } => {
                format!("installed decision model {model_id}")
            }
            ModelSyncOutcome::Rejected { reason } => {
                format!("refused the published model bundle: {reason} (the cached bundle stays)")
            }
            ModelSyncOutcome::FetchFailed { reason } => {
                format!("fetch failed: {reason} (the cached bundle stays)")
            }
            ModelSyncOutcome::NotPublished { url } => {
                format!("HTTP 404 from {url}: the server publishes no decision model")
            }
            ModelSyncOutcome::InstallFailed { reason } => format!("install failed: {reason}"),
        }
    }

    /// Whether the cached bundle is now the published one.
    pub fn is_current(&self) -> bool {
        matches!(
            self,
            ModelSyncOutcome::UpToDate { .. } | ModelSyncOutcome::Installed { .. }
        )
    }
}

/// The bundle store under `<cache>/model/`.
pub struct ModelStore {
    root: PathBuf,
}

impl ModelStore {
    pub fn open(root: &Path) -> anyhow::Result<ModelStore> {
        std::fs::create_dir_all(root)?;
        Ok(ModelStore {
            root: root.to_path_buf(),
        })
    }

    /// Load the cached bundle, verifying the manifest's signature and every
    /// file's digest.
    pub fn load(&self, keyset: &Keyset) -> anyhow::Result<CachedModel> {
        let dir = self.root.join("current");
        let bytes = std::fs::read(dir.join(MANIFEST))
            .map_err(|_| anyhow::anyhow!("no decision model is cached"))?;
        let sig = std::fs::read_to_string(dir.join(SIG)).ok();
        keyset
            .verify_detached(&bytes, sig.as_deref())
            .map_err(|e| anyhow::anyhow!("the cached model manifest does not verify: {e}"))?;
        let manifest = ModelManifest::parse(&bytes)?;
        for f in &manifest.files {
            let on_disk = std::fs::read(dir.join(&f.name))
                .map_err(|e| anyhow::anyhow!("cached model file {}: {e}", f.name))?;
            anyhow::ensure!(
                sha256_hex(&on_disk) == f.sha256,
                "cached model file {} is not the one the manifest signs",
                f.name
            );
        }
        Ok(CachedModel { dir, manifest })
    }

    /// The cached manifest's bytes, if any.
    fn current_manifest(&self) -> Option<Vec<u8>> {
        std::fs::read(self.root.join("current").join(MANIFEST)).ok()
    }

    /// Verify a fetched manifest, fetch the files it lists that the cached
    /// bundle does not already hold, verify each, and swap the bundle in.
    pub fn install(
        &self,
        manifest: &[u8],
        sig_b64: &str,
        keyset: &Keyset,
        fetcher: &dyn ModelFetcher,
    ) -> ModelSyncOutcome {
        let rejected = |reason: String| ModelSyncOutcome::Rejected { reason };
        if let Err(e) = keyset.verify_detached(manifest, Some(sig_b64)) {
            return rejected(e.to_string());
        }
        let m = match ModelManifest::parse(manifest) {
            Ok(m) => m,
            Err(e) => return rejected(format!("{e:#}")),
        };
        if self.current_manifest().as_deref() == Some(manifest) && self.load(keyset).is_ok() {
            return ModelSyncOutcome::UpToDate {
                model_id: m.model_id,
            };
        }
        let current = self.root.join("current");
        let staged = self.root.join("incoming");
        let _ = std::fs::remove_dir_all(&staged);
        if let Err(e) = std::fs::create_dir_all(&staged) {
            return ModelSyncOutcome::InstallFailed {
                reason: e.to_string(),
            };
        }
        for f in &m.files {
            // A file the cached bundle already holds is not fetched again.
            let bytes = match std::fs::read(current.join(&f.name)) {
                Ok(b) if sha256_hex(&b) == f.sha256 => b,
                _ => match fetcher.blob(&format!("{}{}", m.bundle_url, f.sha256)) {
                    Ok(b) => b,
                    Err(e) => {
                        return ModelSyncOutcome::FetchFailed {
                            reason: format!("{}: {e}", f.name),
                        }
                    }
                },
            };
            if sha256_hex(&bytes) != f.sha256 {
                return rejected(format!("{} does not hash to its listed sha256", f.name));
            }
            if let Err(e) = std::fs::write(staged.join(&f.name), &bytes) {
                return ModelSyncOutcome::InstallFailed {
                    reason: e.to_string(),
                };
            }
        }
        let swapped: anyhow::Result<()> = (|| {
            std::fs::write(staged.join(MANIFEST), manifest)?;
            std::fs::write(staged.join(SIG), sig_b64)?;
            let previous = self.root.join("previous");
            let _ = std::fs::remove_dir_all(&previous);
            if current.exists() {
                std::fs::rename(&current, &previous)?;
            }
            std::fs::rename(&staged, &current)?;
            let _ = std::fs::remove_dir_all(&previous);
            Ok(())
        })();
        match swapped {
            Ok(()) => ModelSyncOutcome::Installed {
                model_id: m.model_id,
            },
            Err(e) => ModelSyncOutcome::InstallFailed {
                reason: e.to_string(),
            },
        }
    }
}

/// One model sync: no-op offline, else fetch the manifest and install it.
pub fn sync(
    store: &ModelStore,
    fetcher: &dyn ModelFetcher,
    keyset: &Keyset,
    offline: bool,
) -> ModelSyncOutcome {
    if offline {
        return ModelSyncOutcome::Offline;
    }
    match fetcher.manifest() {
        Ok(FetchedModel::New { manifest, sig_b64 }) => {
            store.install(&manifest, &sig_b64, keyset, fetcher)
        }
        Ok(FetchedModel::NotPublished { url }) => ModelSyncOutcome::NotPublished { url },
        Err(e) => ModelSyncOutcome::FetchFailed {
            reason: e.to_string(),
        },
    }
}

/// The manifest bytes and signature out of the endpoint's response. The
/// manifest is a JSON object inside the response, kept byte for byte; a
/// manifest sent as a JSON string is its string's bytes.
pub fn parse_response(body: &[u8]) -> anyhow::Result<(Vec<u8>, String)> {
    #[derive(Deserialize)]
    struct Response<'a> {
        #[serde(borrow)]
        manifest: &'a RawValue,
        signature: String,
    }
    let r: Response = serde_json::from_slice(body)?;
    let raw = r.manifest.get();
    let manifest = if raw.starts_with('"') {
        serde_json::from_str::<String>(raw)?.into_bytes()
    } else {
        raw.as_bytes().to_vec()
    };
    Ok((manifest, r.signature))
}

/// The HTTP fetcher: the org key as a bearer token on every request.
pub struct HttpModelFetcher {
    pub base_url: String,
    pub org_key: String,
}

impl HttpModelFetcher {
    fn get(&self, path: &str) -> Result<Vec<u8>, ureq::Error> {
        let url = format!("{}{path}", self.base_url.trim_end_matches('/'));
        let resp = crate::http_agent()
            .get(&url)
            .header("Authorization", &format!("Bearer {}", self.org_key))
            .call()?;
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut resp.into_body().into_reader(), &mut bytes)?;
        Ok(bytes)
    }
}

impl ModelFetcher for HttpModelFetcher {
    fn manifest(&self) -> anyhow::Result<FetchedModel> {
        const PATH: &str = "/api/v1/scanner/model";
        match self.get(PATH) {
            Ok(body) => {
                let (manifest, sig_b64) = parse_response(&body)?;
                Ok(FetchedModel::New { manifest, sig_b64 })
            }
            Err(ureq::Error::StatusCode(404)) => Ok(FetchedModel::NotPublished {
                url: format!("{}{PATH}", self.base_url.trim_end_matches('/')),
            }),
            Err(e) => Err(e.into()),
        }
    }

    fn blob(&self, path: &str) -> anyhow::Result<Vec<u8>> {
        Ok(self.get(path)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_response_keeps_the_manifest_bytes_as_sent() {
        let body = br#"{"manifest": {"b":1,  "a":[2]}, "signature":"c2ln"}"#;
        let (m, sig) = parse_response(body).unwrap();
        assert_eq!(m, br#"{"b":1,  "a":[2]}"#);
        assert_eq!(sig, "c2ln");
        let quoted = br#"{"manifest":"{\"a\":1}","signature":"s"}"#;
        assert_eq!(parse_response(quoted).unwrap().0, br#"{"a":1}"#);
    }

    fn manifest(files: &str, extra: &str) -> String {
        format!(
            r#"{{"schema_version":1,"model_id":"m","layout":"compact","max_len":8,
            "temperature":2.0,"bundle_url":"/api/v1/scanner/model/blobs/",
            "served_controls":[{{"control":"RC-019","precision":0.9,"ece":0.01}}],
            "withheld_controls":["RC-022"],"files":{files}{extra}}}"#
        )
    }

    const SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn a_manifest_parses_with_unknown_fields_and_either_control_shape() {
        let files = format!(
            r#"[{{"name":"model.int8.onnx","sha256":"{SHA}","size":0}},
            {{"name":"tokenizer.json","sha256":"{SHA}"}}]"#
        );
        let m = ModelManifest::parse(manifest(&files, r#","later":{"x":1}"#).as_bytes()).unwrap();
        assert!(m.serves("RC-019") && !m.serves("RC-022"));
        assert_eq!(m.withheld_controls[0].control, "RC-022");
        assert_eq!(m.model_file().name, "model.int8.onnx");
    }

    #[test]
    fn a_manifest_that_could_escape_or_mislead_is_refused() {
        let file = |name: &str, sha: &str| format!(r#"{{"name":"{name}","sha256":"{sha}"}}"#);
        let tok = file("tokenizer.json", SHA);
        for files in [
            format!("[{tok}]"),
            format!("[{},{tok}]", file("../model.onnx", SHA)),
            format!("[{},{tok}]", file("model.onnx", "abc")),
            format!("[{},{},{tok}]", file("a.onnx", SHA), file("b.onnx", SHA)),
            format!("[{},{tok},{tok}]", file("model.onnx", SHA)),
            format!("[{}]", file("model.onnx", SHA)),
        ] {
            assert!(
                ModelManifest::parse(manifest(&files, "").as_bytes()).is_err(),
                "accepted {files}"
            );
        }
        let ok = format!("[{},{tok}]", file("model.onnx", SHA));
        let off_site = manifest(&ok, "").replace(
            "\"/api/v1/scanner/model/blobs/\"",
            "\"https://elsewhere.example/\"",
        );
        assert!(ModelManifest::parse(off_site.as_bytes()).is_err());
        let v2 = manifest(&ok, "").replace("\"schema_version\":1", "\"schema_version\":2");
        let err = ModelManifest::parse(v2.as_bytes()).unwrap_err().to_string();
        assert!(err.contains("schema_version 2"), "{err}");
    }
}
