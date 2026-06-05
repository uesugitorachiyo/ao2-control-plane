use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;
use tokio::fs::{self, File};
use tokio::io::AsyncWriteExt;

/// Process-local counter that keeps temp filenames unique across concurrent
/// writers, so two writers of the same sha never collide on the same temp path.
static WRITE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleKind {
    AcceptanceCodex,
    AcceptanceClaude,
    AcceptanceAntigravity,
    ControlPlaneBundle,
    EvidencePack,
    EvidencePackSignature,
    HermesWatchdogPanel,
    MemoryExport,
    MemoryExportSignature,
    Phase1PromotionChecklist,
    Phase1PromotionDecision,
    Phase1PromotionDecisionSignature,
    Phase1PromotionInputsVerification,
    ProviderReadiness,
    ProviderReadinessSignature,
    ProviderRegistry,
    ProviderRegistrySignature,
    ReleaseEvaluatorDecision,
    ReleaseEvaluatorDecisionSignature,
    ReleasePublication,
    ThreeOsReleaseSmoke,
}

impl BundleKind {
    pub fn subdir(&self) -> &'static str {
        match self {
            BundleKind::AcceptanceCodex => "acceptance/codex",
            BundleKind::AcceptanceClaude => "acceptance/claude",
            BundleKind::AcceptanceAntigravity => "acceptance/antigravity",
            BundleKind::ControlPlaneBundle => "control-plane-bundle",
            BundleKind::EvidencePack => "evidence-pack",
            BundleKind::EvidencePackSignature => "evidence-pack-signature",
            BundleKind::HermesWatchdogPanel => "hermes-watchdog-panel",
            BundleKind::MemoryExport => "memory-export",
            BundleKind::MemoryExportSignature => "memory-export-signature",
            BundleKind::Phase1PromotionChecklist => "phase1-promotion-checklist",
            BundleKind::Phase1PromotionDecision => "phase1-promotion-decision",
            BundleKind::Phase1PromotionDecisionSignature => "phase1-promotion-decision-signature",
            BundleKind::Phase1PromotionInputsVerification => "phase1-promotion-inputs-verification",
            BundleKind::ProviderReadiness => "provider-readiness",
            BundleKind::ProviderReadinessSignature => "provider-readiness-signature",
            BundleKind::ProviderRegistry => "provider-registry",
            BundleKind::ProviderRegistrySignature => "provider-registry-signature",
            BundleKind::ReleaseEvaluatorDecision => "release-evaluator-decision",
            BundleKind::ReleaseEvaluatorDecisionSignature => "release-evaluator-decision-signature",
            BundleKind::ReleasePublication => "release-publication",
            BundleKind::ThreeOsReleaseSmoke => "three-os-release-smoke",
        }
    }
}

#[derive(Debug, Error)]
pub enum BundleStoreError {
    #[error("bundle not found: {0}")]
    NotFound(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct BundleStore {
    root: PathBuf,
}

impl BundleStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn path(&self, kind: BundleKind, sha256: &str) -> PathBuf {
        self.root.join(kind.subdir()).join(format!("{sha256}.json"))
    }

    pub async fn write(
        &self,
        kind: BundleKind,
        sha256: &str,
        bytes: &[u8],
    ) -> Result<(), BundleStoreError> {
        let path = self.path(kind, sha256);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        // Atomic publish: write to a unique temp file in the same directory,
        // fsync it, then rename into place. A concurrent reader therefore
        // observes either no file or the complete file — never a torn or
        // truncated one — and a crash mid-write leaves an orphan `.tmp` rather
        // than a corrupt bundle sitting at the canonical content-addressed
        // path. Mirrors `IndexStore::rewrite`.
        //
        // The pid + process-local counter keep the temp name unique, so two
        // concurrent writers of the same sha (legal — identical content) never
        // collide on the temp path; the rename is then last-writer-wins over
        // byte-identical content, which is safe for a content-addressed store.
        // The `.json.tmp.*` suffix also means `list()` (which matches `.json`)
        // never surfaces an in-flight temp as a bundle.
        let unique = WRITE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = path.with_extension(format!("json.tmp.{}.{unique}", std::process::id()));
        if let Err(e) = write_tmp_then_rename(&tmp, &path, bytes).await {
            // Best-effort cleanup so a failed write leaves no orphan temp.
            let _ = fs::remove_file(&tmp).await;
            return Err(e);
        }
        Ok(())
    }

    pub async fn read(&self, kind: BundleKind, sha256: &str) -> Result<Vec<u8>, BundleStoreError> {
        let path = self.path(kind, sha256);
        match fs::read(&path).await {
            Ok(b) => Ok(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(BundleStoreError::NotFound(sha256.to_string()))
            }
            Err(e) => Err(BundleStoreError::Io(e)),
        }
    }

    pub async fn exists(&self, kind: BundleKind, sha256: &str) -> bool {
        fs::metadata(self.path(kind, sha256)).await.is_ok()
    }

    pub async fn size(&self, kind: BundleKind, sha256: &str) -> Result<u64, BundleStoreError> {
        let path = self.path(kind, sha256);
        match fs::metadata(&path).await {
            Ok(metadata) => Ok(metadata.len()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(BundleStoreError::NotFound(sha256.to_string()))
            }
            Err(e) => Err(BundleStoreError::Io(e)),
        }
    }

    pub async fn remove_if_exists(
        &self,
        kind: BundleKind,
        sha256: &str,
    ) -> Result<bool, BundleStoreError> {
        let path = self.path(kind, sha256);
        match fs::remove_file(&path).await {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(BundleStoreError::Io(e)),
        }
    }

    pub async fn list(&self, kind: BundleKind) -> Result<Vec<String>, BundleStoreError> {
        let dir = self.root.join(kind.subdir());
        if !dir.exists() {
            return Ok(vec![]);
        }
        let mut out = Vec::new();
        let mut entries = fs::read_dir(&dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(sha) = name.strip_suffix(".json") {
                out.push(sha.to_string());
            }
        }
        Ok(out)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// Write `bytes` to `tmp`, fsync, then atomically rename `tmp` onto `path`.
/// Kept symmetric with `IndexStore::rewrite` (File::create + write_all +
/// sync_data + rename) so the durability guarantees match across the store.
async fn write_tmp_then_rename(
    tmp: &Path,
    path: &Path,
    bytes: &[u8],
) -> Result<(), BundleStoreError> {
    {
        let mut file = File::create(tmp).await?;
        file.write_all(bytes).await?;
        file.sync_data().await?;
    }
    fs::rename(tmp, path).await?;
    Ok(())
}
