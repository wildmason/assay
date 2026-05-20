//! Assay run receipt writer.
//!
//! Writes the `RunStoreReceipt`-shaped `run.json` under
//! `.assay/runs/<run-id>/` along with per-stage receipt JSON files
//! and any stage logs. The envelope is symmetric enough with `.assay/runs/`
//! that a future shared index loader can read both stores.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::{Error, Result};
use crate::model::AssayRunReceipt;

/// Write the top-level run receipt into a runs subdirectory keyed
/// by run id. Creates the directory tree if needed. Returns the path of
/// the written `run.json`.
pub fn write_run_receipt(workspace_root: &Path, receipt: &AssayRunReceipt) -> Result<PathBuf> {
    let run_dir = workspace_root
        .join(".assay")
        .join("runs")
        .join(&receipt.run_id);
    fs::create_dir_all(&run_dir).map_err(|source| Error::Io {
        path: run_dir.clone(),
        source,
    })?;
    // `logs/` and `receipts/` subdirs are created lazily by
    // `write_stage_receipt` / log writers when something actually
    // lands there. Pre-creating them under DryRun (the most common
    // mode) littered every run directory with two empty subdirs —
    // multiple dogfood agents read that as "the run aborted partway."
    let run_json_path = run_dir.join("run.json");
    let json = serde_json::to_string_pretty(receipt).map_err(Error::Json)?;
    fs::write(&run_json_path, json).map_err(|source| Error::Io {
        path: run_json_path.clone(),
        source,
    })?;
    Ok(run_json_path)
}

/// Write a per-stage receipt JSON next to the run receipt.
pub fn write_stage_receipt<T: Serialize>(
    workspace_root: &Path,
    run_id: &str,
    stage_filename: &str,
    payload: &T,
) -> Result<PathBuf> {
    let receipts_dir = workspace_root
        .join(".assay")
        .join("runs")
        .join(run_id)
        .join("receipts");
    fs::create_dir_all(&receipts_dir).map_err(|source| Error::Io {
        path: receipts_dir.clone(),
        source,
    })?;
    let receipt_path = receipts_dir.join(stage_filename);
    let json = serde_json::to_string_pretty(payload).map_err(Error::Json)?;
    fs::write(&receipt_path, json).map_err(|source| Error::Io {
        path: receipt_path.clone(),
        source,
    })?;
    Ok(receipt_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AssayRunReceipt, Classification, Provenance, ProvenanceRecord, RepositoryRef, RunSummary,
    };

    fn sample_receipt(run_id: &str) -> AssayRunReceipt {
        AssayRunReceipt {
            schema_version: 1,
            run_id: run_id.to_string(),
            started_at: "2026-05-16T19:30:00Z".to_string(),
            finished_at: "2026-05-16T19:34:12Z".to_string(),
            repository: RepositoryRef {
                path: "/tmp/repo".into(),
                github: Some("wildmason/example".into()),
                git_ref: Some("main".into()),
            },
            run_context: None,
            summary: RunSummary {
                manifests_scanned: 2,
                proposals_total: 1,
                proposals_passed: 1,
                proposals_failed: 0,
                proposals_unvalidated: 0,
                proposals_discovered: 0,
                proposals_merged_dropped: 0,
                proposals_shipped: 1,
                prs_opened: 0,
            },
            provenance: Provenance {
                records: vec![ProvenanceRecord {
                    tool: "assay".into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    stage: "scanner".into(),
                    subject: "Cargo.lock".into(),
                    status: Classification::Exact,
                    summary: "scanned 2 manifests".into(),
                    artifact_path: None,
                    details: None,
                }],
            },
        }
    }

    #[test]
    fn write_run_receipt_creates_run_dir_only() {
        // logs/ and receipts/ are created lazily by stage writers — a
        // DryRun receipt-only invocation leaves them absent. The
        // dogfood feedback was that empty subdirs read as "this run
        // aborted partway" — better to materialize them only when
        // something actually writes there.
        let tmp = tempfile::tempdir().unwrap();
        let receipt = sample_receipt("assay-test-1");
        let path = write_run_receipt(tmp.path(), &receipt).unwrap();
        assert!(path.ends_with("run.json"));
        assert!(path.exists());
        let run_dir = tmp.path().join(".assay").join("runs").join("assay-test-1");
        assert!(!run_dir.join("receipts").exists());
        assert!(!run_dir.join("logs").exists());
    }

    #[test]
    fn write_stage_receipt_materializes_receipts_subdir_lazily() {
        // The complement to above: as soon as a stage writes a
        // receipt, the receipts/ subdir appears.
        let tmp = tempfile::tempdir().unwrap();
        let receipt = sample_receipt("assay-test-lazy");
        write_run_receipt(tmp.path(), &receipt).unwrap();
        let run_dir = tmp
            .path()
            .join(".assay")
            .join("runs")
            .join("assay-test-lazy");
        assert!(!run_dir.join("receipts").exists());
        write_stage_receipt(
            tmp.path(),
            "assay-test-lazy",
            "stage.json",
            &serde_json::json!({"ok": true}),
        )
        .unwrap();
        assert!(run_dir.join("receipts").is_dir());
    }

    #[test]
    fn write_run_receipt_persists_schema_version_and_records() {
        let tmp = tempfile::tempdir().unwrap();
        let receipt = sample_receipt("assay-test-2");
        let path = write_run_receipt(tmp.path(), &receipt).unwrap();
        let json = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["run_id"], "assay-test-2");
        assert_eq!(parsed["provenance"]["records"][0]["stage"], "scanner");
        assert_eq!(parsed["provenance"]["records"][0]["status"], "exact");
    }

    #[test]
    fn write_stage_receipt_places_under_receipts_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let receipt = sample_receipt("assay-test-3");
        write_run_receipt(tmp.path(), &receipt).unwrap();
        let payload = serde_json::json!({ "subject": "cargo-serde-1-0-215", "result": "passed" });
        let stage_path = write_stage_receipt(
            tmp.path(),
            "assay-test-3",
            "validator-cargo-serde-1-0-215.json",
            &payload,
        )
        .unwrap();
        assert!(stage_path.exists());
        assert!(
            stage_path.components().any(|c| c.as_os_str() == "receipts"),
            "stage receipt must be under receipts/: {}",
            stage_path.display()
        );
        let read_back: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&stage_path).unwrap()).unwrap();
        assert_eq!(read_back["result"], "passed");
    }
}
