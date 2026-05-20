//! npm / pnpm ecosystem.
//!
//! Detects `package.json` + a lockfile (`package-lock.json`, `pnpm-lock.yaml`,
//! or `yarn.lock`) and proposes version bumps by shelling out to the matching
//! package manager's `outdated` reporter. Both npm and pnpm emit a
//! near-identical JSON shape:
//!
//! ```json
//! {
//!   "lodash": {
//!     "current": "4.17.20",
//!     "wanted":  "4.17.21",
//!     "latest":  "5.0.0"
//!   }
//! }
//! ```
//!
//! - `current` — what's resolved in the lockfile.
//! - `wanted` — highest in-range version (lockfile would pick this on
//!   `npm update <pkg>`).
//! - `latest` — most recent publish on the registry.
//!
//! Tier mapping:
//! - `wanted == latest` → [`BumpTier::LockfileOnly`]. Constraint allows
//!   latest; only the lockfile needs to change.
//! - `wanted != latest` → [`BumpTier::Compatible`] or [`BumpTier::Breaking`]
//!   based on the caret-compat group of (`current`, `latest`). The
//!   manifest constraint must be widened.
//!
//! Yarn 1 emits a different NDJSON shape (`{"type":"table","data":{...}}`)
//! which the proposer parses via `parse_yarn1_outdated_output`. The
//! applier shells out to `yarn upgrade <pkg>@<v> --exact` with the same
//! snapshot/restore wrapper used for npm LockfileOnly bumps. Yarn 2+
//! ("Berry") offers `yarn npm outdated --json` in the npm shape and
//! could be added later — it falls through the npm path if the operator
//! has set up `nodeLinker: node-modules`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::model::{
    BumpTier, Classification, ConsumerId, Manifest, ManifestKind, Proposal, ProposalKind,
    ValidationOutcome,
};
use crate::process_runner::{RunResult, run_with_timeout};

use super::{DependencyEcosystem, EcosystemContext, EcosystemName};

/// Lockfile flavor the project uses. Determines which `outdated` command
/// the proposer invokes and which lockfile path the copy-back ships.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NpmFlavor {
    /// `package-lock.json` — invoke `npm`.
    Npm,
    /// `pnpm-lock.yaml` — invoke `pnpm`.
    Pnpm,
    /// `yarn.lock` (yarn 1 / "classic") — invoke `yarn`. Distinguished
    /// from [`NpmFlavor::YarnBerry`] by the absence of the
    /// `__metadata:` header at the top of the lockfile.
    Yarn,
    /// `yarn.lock` (yarn ≥ 2 / "berry"). Berry core has no built-in
    /// `outdated` command, so the proposer walks direct deps from
    /// package.json and queries `yarn npm info <pkg> --json` per dep
    /// to compute proposals. Apply uses `yarn up <pkg>@<ver>`.
    YarnBerry,
}

impl NpmFlavor {
    fn lockfile_name(self) -> &'static str {
        match self {
            NpmFlavor::Npm => "package-lock.json",
            NpmFlavor::Pnpm => "pnpm-lock.yaml",
            NpmFlavor::Yarn | NpmFlavor::YarnBerry => "yarn.lock",
        }
    }
}

fn detect_flavor(repo: &Path) -> Option<NpmFlavor> {
    // Order matters: npm + pnpm lockfiles are unambiguous. yarn.lock
    // is shared between yarn1 and berry; the `__metadata:` peek
    // disambiguates. If somehow both yarn.lock and one of the others
    // are present (a corrupt repo), npm/pnpm take precedence to match
    // pre-berry behavior.
    if repo.join("package-lock.json").is_file() {
        return Some(NpmFlavor::Npm);
    }
    if repo.join("pnpm-lock.yaml").is_file() {
        return Some(NpmFlavor::Pnpm);
    }
    if repo.join("yarn.lock").is_file() {
        return if yarn_lock_is_berry(repo) {
            Some(NpmFlavor::YarnBerry)
        } else {
            Some(NpmFlavor::Yarn)
        };
    }
    None
}

/// Returns `true` when `yarn.lock` at `repo` is in the yarn berry
/// (yarn ≥ 2) format. Berry files open with a `__metadata:` header
/// block. Yarn 1's lockfile has no such block — entries start
/// immediately with the package descriptor (`<name>@<version>:` form).
///
/// This is a cheap content peek (first ~512 bytes); we don't parse the
/// whole file. Falsey on read errors so the caller still attempts
/// proposal generation rather than spuriously bailing on a transient
/// filesystem hiccup.
fn yarn_lock_is_berry(repo: &Path) -> bool {
    let path = repo.join("yarn.lock");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return false;
    };
    // Cap the inspection — large yarn.lock files (a few hundred KB) are
    // common and we don't want to materialize the whole thing just to
    // sniff the header.
    text.lines()
        .take(50)
        .any(|line| line.trim() == "__metadata:")
}

#[derive(Debug, Default, Clone)]
pub struct NpmEcosystem;

impl DependencyEcosystem for NpmEcosystem {
    fn name(&self) -> &'static str {
        EcosystemName::Npm.as_str()
    }

    fn detect_manifests(&self, repo: &Path) -> Result<Vec<Manifest>> {
        if !repo.is_dir() {
            return Err(Error::RepoNotFound(repo.to_path_buf()));
        }
        let mut found = Vec::new();
        let package_json = repo.join("package.json");
        let package_json_present = package_json.is_file();
        if package_json_present {
            found.push(Manifest {
                path: PathBuf::from("package.json"),
                kind: ManifestKind::PackageJson,
                metadata: BTreeMap::new(),
            });
        }
        // Don't report orphan lockfiles (lockfile without sibling
        // package.json) as detected manifests — propose_updates would
        // return empty and the operator would see "1 manifest, 0
        // proposals" with no explanation (mortar dogfood: empty root
        // `package-lock.json` short-circuited polyglot traversal AND
        // looked like a successful scan). Polyglot detection still
        // discovers the real `ui/package.json` separately.
        if package_json_present && let Some(flavor) = detect_flavor(repo) {
            found.push(Manifest {
                path: PathBuf::from(flavor.lockfile_name()),
                kind: ManifestKind::NpmLockfile,
                metadata: BTreeMap::new(),
            });
        }
        Ok(found)
    }

    fn propose_updates(
        &self,
        manifests: &[Manifest],
        repo: &Path,
        ctx: &EcosystemContext,
    ) -> Result<Vec<Proposal>> {
        let has_package_json = manifests
            .iter()
            .any(|m| matches!(m.kind, ManifestKind::PackageJson));
        if !has_package_json {
            return Ok(Vec::new());
        }
        let Some(flavor) = detect_flavor(repo) else {
            return Ok(Vec::new());
        };
        let manifest_paths: Vec<PathBuf> = manifests
            .iter()
            .filter(|m| {
                matches!(
                    m.kind,
                    ManifestKind::PackageJson | ManifestKind::NpmLockfile
                )
            })
            .map(|m| m.path.clone())
            .collect();
        let mut proposals = run_npm_proposer(flavor, repo, &manifest_paths)?;
        tag_proposals_with_cohorts(&mut proposals);
        widen_cohort_tiers(&mut proposals);
        annotate_proposals_with_overrides(&mut proposals, repo);
        Ok(filter_ignored_packages(proposals, &ctx.ignored_subjects))
    }

    fn gate_workflows(&self, _proposal: &Proposal, repo: &Path) -> Result<Vec<PathBuf>> {
        let workflows_dir = repo.join(".github").join("workflows");
        if !workflows_dir.is_dir() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&workflows_dir).map_err(|source| Error::Io {
            path: workflows_dir.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| Error::Io {
                path: workflows_dir.clone(),
                source,
            })?;
            let path = entry.path();
            let extension = path.extension().and_then(|e| e.to_str());
            if matches!(extension, Some("yml") | Some("yaml")) {
                let rel = path
                    .strip_prefix(repo)
                    .map(Path::to_path_buf)
                    .unwrap_or(path);
                out.push(rel);
            }
        }
        out.sort();
        Ok(out)
    }

    fn affected_consumers(&self, proposal: &Proposal, tree: &Path) -> Result<Vec<ConsumerId>> {
        resolve_npm_consumers(proposal, tree)
    }

    fn apply_proposal(&self, proposal: &Proposal, tree_path: &Path) -> Result<()> {
        let Some(flavor) = detect_flavor(tree_path) else {
            return Err(Error::other(format!(
                "no npm/pnpm lockfile found in `{}`; cannot apply bump",
                tree_path.display()
            )));
        };
        apply_npm_proposal(flavor, proposal, tree_path)
    }

    fn copy_back(&self, _proposal: &Proposal, sandbox: &Path, host: &Path) -> Result<Vec<PathBuf>> {
        copy_back_npm_sandbox(sandbox, host)
    }

    fn copy_back_merged(
        &self,
        _proposals: &[&Proposal],
        sandbox: &Path,
        host: &Path,
    ) -> Result<Vec<PathBuf>> {
        // For npm, copy-back is bulk-by-design (the whole package.json
        // and lockfile pair). Each per-proposal copy_back would just
        // re-ship the same bytes, so the merged path collapses to ONE
        // bulk copy from the merged sandbox to host.
        copy_back_npm_sandbox(sandbox, host)
    }

    fn pr_body_fragment(&self, proposal: &Proposal, outcome: &ValidationOutcome) -> String {
        format!(
            "- **{pkg}**: `{from}` → `{to}` ({classification})",
            pkg = proposal.subject,
            from = proposal.from,
            to = proposal.to,
            classification = outcome.classification.as_str(),
        )
    }
}

/// Bulk copy-back: ship the sandbox's `package.json` + flavor-specific
/// lockfile to host. Used by both the per-proposal `copy_back` and the
/// merged-set `copy_back_merged` because the unit of change for npm is
/// always the whole manifest+lockfile pair regardless of how many
/// proposals contributed to the sandbox state.
///
/// Also walks workspace members (npm/yarn `workspaces` + pnpm-workspace.yaml)
/// and ships any member `package.json` whose bytes differ between sandbox
/// and host — Compatible / Breaking bumps widen constraints in each
/// consuming member, and skipping those leaves the host commit out of
/// sync with the validated state.
fn copy_back_npm_sandbox(sandbox: &Path, host: &Path) -> Result<Vec<PathBuf>> {
    let Some(flavor) = detect_flavor(sandbox) else {
        return Err(Error::other(format!(
            "no lockfile in sandbox at `{}`; cannot copy back",
            sandbox.display()
        )));
    };
    let mut copied = Vec::new();
    let mut copy_if_differs = |relative: PathBuf| -> Result<()> {
        let sb = sandbox.join(&relative);
        if !sb.is_file() {
            return Ok(());
        }
        let host_path = host.join(&relative);
        let sb_bytes = std::fs::read(&sb).map_err(|source| Error::Io {
            path: sb.clone(),
            source,
        })?;
        let host_bytes = std::fs::read(&host_path).unwrap_or_default();
        if sb_bytes == host_bytes {
            return Ok(());
        }
        std::fs::copy(&sb, &host_path).map_err(|source| Error::Io {
            path: host_path,
            source,
        })?;
        copied.push(relative);
        Ok(())
    };
    copy_if_differs(PathBuf::from("package.json"))?;
    copy_if_differs(PathBuf::from(flavor.lockfile_name()))?;
    // Workspace members: copy any whose bytes differ. Discovery runs
    // against the sandbox tree because the merge applier may have
    // widened member manifests in there.
    for member in detect_workspace_members(sandbox)? {
        copy_if_differs(member.relative_path.join("package.json"))?;
    }
    copied.sort();
    copied.dedup();
    Ok(copied)
}

/// Single entry from `npm outdated --json` / `pnpm outdated --format=json`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct OutdatedEntry {
    /// Resolved version in the lockfile. May be absent when the package
    /// is in `package.json` but hasn't been installed yet.
    #[serde(default)]
    current: Option<String>,
    /// Highest version that satisfies the current constraint. Absent
    /// when pnpm reports a `file:` / `link:` / `workspace:` dep — those
    /// have no registry-side "wanted" to bump to and are skipped by
    /// the proposer.
    #[serde(default)]
    wanted: Option<String>,
    /// Most recent publish on the registry. Absent for the same
    /// non-registry dep flavors as `wanted` above.
    #[serde(default)]
    latest: Option<String>,
}

/// One JSON value per dep emitted by `npm outdated --json`.
///
/// In a flat (single-project) project the shape is one [`OutdatedEntry`]
/// per dep. In a workspace project (npm 7+ workspaces) it's an **array**
/// of entries — one per consuming member — so the same dep can appear
/// multiple times with the same (current, wanted, latest) tuple but
/// different `dependent` values. The first entry suffices for proposal
/// generation because npm hoists workspace deps to the root
/// `node_modules`, so every consumer sees the same resolved version.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum OutdatedValue {
    Single(OutdatedEntry),
    PerConsumer(Vec<OutdatedEntry>),
}

/// Parsed proposal-ready entry combining the dep name with its versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NpmOutdatedRow {
    pub name: String,
    pub current: Option<String>,
    pub wanted: String,
    pub latest: String,
}

/// Parses the JSON object emitted by `npm outdated --json` /
/// `pnpm outdated --format=json`. Returns rows sorted by name so
/// downstream proposal IDs are deterministic across runs.
///
/// Empty input (no outdated packages, both reporters emit `{}` and exit
/// non-zero from npm — but with `--json` the body is still well-formed
/// JSON) parses to an empty Vec.
///
/// Handles both the flat (single-project) shape `{ "lodash": {...} }`
/// and the workspace shape `{ "lodash": [ {...}, {...} ] }` that npm 7+
/// emits when the project has workspaces. Per-consumer arrays are
/// collapsed to one row per dep using the first entry — assay treats
/// the bump as a single workspace-level event; per-member dep
/// declarations are surfaced via [`affected_consumers`] downstream.
pub(crate) fn parse_npm_outdated_output(stdout: &str) -> Result<Vec<NpmOutdatedRow>> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let parsed: BTreeMap<String, OutdatedValue> = serde_json::from_str(trimmed)
        .map_err(|e| Error::other(format!("npm outdated JSON: {e}")))?;
    let mut rows: Vec<NpmOutdatedRow> = Vec::new();
    for (name, value) in parsed {
        let entry = match value {
            OutdatedValue::Single(e) => e,
            OutdatedValue::PerConsumer(entries) => match entries.into_iter().next() {
                Some(e) => e,
                None => continue,
            },
        };
        // Skip non-registry deps (`file:`, `link:`, `workspace:`) — pnpm
        // -r emits these with `wanted` or `latest` absent (or a path-shaped
        // `wanted`), and there's no registry-side version to bump to.
        let (Some(wanted), Some(latest)) = (entry.wanted, entry.latest) else {
            continue;
        };
        rows.push(NpmOutdatedRow {
            name,
            current: entry.current,
            wanted,
            latest,
        });
    }
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(rows)
}

/// Parse yarn1's `yarn outdated --json` output (newline-delimited JSON).
///
/// Yarn 1 wraps the actual data in a table envelope:
///
/// ```text
/// {"type":"info","data":"Color legend : ..."}
/// {"type":"table","data":{"head":["Package","Current","Wanted","Latest","Package Type","URL"],
///   "body":[["lodash","4.17.20","4.17.21","4.18.1","dependencies","https://lodash.com/"]]}}
/// ```
///
/// Each `body` row carries `[name, current, wanted, latest, package_type,
/// url]`. We pick the first `type: "table"` line and emit one row per
/// body entry.
///
/// Returns an empty Vec when the stream contains no `table` line (yarn
/// emits `{"type":"info",...}` even when nothing is outdated).
pub(crate) fn parse_yarn1_outdated_output(stdout: &str) -> Result<Vec<NpmOutdatedRow>> {
    let mut rows: Vec<NpmOutdatedRow> = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            continue;
        };
        let kind = value.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if kind != "table" {
            continue;
        }
        let Some(data) = value.get("data") else {
            continue;
        };
        let Some(body) = data.get("body").and_then(|v| v.as_array()) else {
            continue;
        };
        for entry in body {
            let Some(cells) = entry.as_array() else {
                continue;
            };
            if cells.len() < 4 {
                continue;
            }
            let Some(name) = cells.first().and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(current) = cells.get(1).and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(wanted) = cells.get(2).and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(latest) = cells.get(3).and_then(|v| v.as_str()) else {
                continue;
            };
            rows.push(NpmOutdatedRow {
                name: name.to_string(),
                current: Some(current.to_string()),
                wanted: wanted.to_string(),
                latest: latest.to_string(),
            });
        }
        // Stop after the first table — yarn1 emits only one.
        break;
    }
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(rows)
}

/// Builds proposals from parsed outdated rows. Tier mapping mirrors
/// cargo's: when the lockfile-wanted version equals the registry latest,
/// the bump only needs `npm update` (LockfileOnly). When it doesn't,
/// the constraint blocks the latest and tier classification falls back
/// to the caret-compat-group comparison between current and latest.
///
/// Rows with no `current` (package declared but never installed) are
/// skipped — we have no "from" to compare against.
pub(crate) fn build_npm_proposals(
    rows: &[NpmOutdatedRow],
    manifest_paths: &[PathBuf],
) -> Vec<Proposal> {
    let mut proposals = Vec::new();
    for row in rows {
        let Some(current) = row.current.as_deref() else {
            continue;
        };
        // When `npm outdated` runs without a populated node_modules it
        // includes every package, even ones where the lockfile already
        // matches the registry latest. Drop those — there's nothing to
        // bump.
        if current == row.latest {
            continue;
        }
        let tier = if row.wanted == row.latest {
            BumpTier::LockfileOnly
        } else {
            classify_npm_bump(current, &row.latest)
        };
        let id = format!(
            "npm-{}-{}-to-{}",
            sanitize_id_segment(&row.name),
            sanitize_id_segment(current),
            sanitize_id_segment(&row.latest),
        );
        proposals.push(Proposal {
            id,
            ecosystem: EcosystemName::Npm.as_str().to_string(),
            kind: ProposalKind::Version,
            subject: row.name.clone(),
            from: current.to_string(),
            to: row.latest.clone(),
            initial_classification: Classification::Exact,
            manifest_paths: manifest_paths.to_vec(),
            notes: Vec::new(),
            bump_tier: tier,
            affected_consumers: Vec::new(),
            explanation: None,
            cohort: None,
        });
    }
    proposals
}

/// Classify an npm version bump into a [`BumpTier`].
///
/// npm uses the same compatibility-group concept as Cargo (caret matches
/// within the same significant segment), so the rules mirror
/// `classify_unchanged_bump` in `cargo.rs`:
///
/// - `major >= 1`: same major group → Compatible.
/// - `0.y.z`: same minor group → Compatible.
/// - `0.0.z`: same patch group → Compatible (i.e. only identical bumps).
///
/// Defensive: unparseable input returns Breaking so the operator gets
/// a chance to look rather than a silent skip.
pub(crate) fn classify_npm_bump(from: &str, to: &str) -> BumpTier {
    let Ok(from_v) = semver::Version::parse(from) else {
        return BumpTier::Breaking;
    };
    let Ok(to_v) = semver::Version::parse(to) else {
        return BumpTier::Breaking;
    };
    if compat_group(&from_v) == compat_group(&to_v) {
        BumpTier::Compatible
    } else {
        BumpTier::Breaking
    }
}

fn compat_group(v: &semver::Version) -> (u64, u64, u64) {
    match (v.major, v.minor) {
        (0, 0) => (0, 0, v.patch),
        (0, _) => (0, v.minor, 0),
        _ => (v.major, 0, 0),
    }
}

/// Build a structured [`crate::model::BumpExplanation`] for an npm
/// version bump, paralleling [`classify_npm_bump`]. npm and cargo
/// share the caret-compat model; the explanation mirrors the wording
/// the cargo explainer uses but flags the ecosystem as npm so the
/// report attribution is correct.
pub(crate) fn explain_npm_bump(from: &str, to: &str) -> crate::model::BumpExplanation {
    use crate::model::BumpExplanation;
    use std::collections::BTreeMap;

    let mut inputs = BTreeMap::new();
    inputs.insert("from".into(), from.to_string());
    inputs.insert("to".into(), to.to_string());

    let (from_v, to_v) = match (semver::Version::parse(from), semver::Version::parse(to)) {
        (Ok(f), Ok(t)) => (f, t),
        _ => {
            return BumpExplanation {
                summary: format!(
                    "npm: one or both versions unparseable as semver ({from} -> {to}); \
                     classified Breaking conservatively so the operator reviews"
                ),
                rule: "npm:unparseable-semver".into(),
                inputs,
                decision: "breaking".into(),
            };
        }
    };
    let from_group = compat_group(&from_v);
    let to_group = compat_group(&to_v);
    inputs.insert(
        "from_compat_group".into(),
        format!("{}.{}.{}", from_group.0, from_group.1, from_group.2),
    );
    inputs.insert(
        "to_compat_group".into(),
        format!("{}.{}.{}", to_group.0, to_group.1, to_group.2),
    );

    if from_group == to_group {
        let rule = match (from_v.major, from_v.minor) {
            (0, 0) => "npm:caret-0-0-x-same-patch",
            (0, _) => "npm:caret-0-x-same-minor",
            _ => "npm:caret-major-1-plus",
        };
        let summary = match (from_v.major, from_v.minor) {
            (0, 0) => format!(
                "npm: 0.0.x band — each patch is its own caret group; {from} and {to} share \
                 patch={}, so only the manifest pin keeps npm from bumping (Compatible)",
                from_v.patch
            ),
            (0, _) => format!(
                "npm: 0.x band — caret groups by minor; both versions share minor={}, so \
                 only the manifest pin keeps npm from bumping (Compatible)",
                from_v.minor
            ),
            _ => format!(
                "npm: 1.0+ band — caret groups by major; both versions share major={}, so \
                 only the manifest pin keeps npm from bumping (Compatible)",
                from_v.major
            ),
        };
        BumpExplanation {
            summary,
            rule: rule.into(),
            inputs,
            decision: "compatible".into(),
        }
    } else {
        let rule = match (from_v.major, from_v.minor) {
            (0, 0) => "npm:caret-0-0-x-patch-crossed",
            (0, _) if from_v.minor != to_v.minor => "npm:caret-0-x-minor-crossed",
            _ if from_v.major != to_v.major => "npm:caret-major-crossed",
            _ => "npm:caret-group-crossed",
        };
        // Each summary names the rule once and the input boundary
        // once — the previous form repeated both halves in slightly
        // different words (dogfood-flagged as stuttering). Each also
        // hints at the implied manifest edit the operator will need
        // to widen the caret constraint (`^{from} → ^{to}`).
        let summary = match (from_v.major, from_v.minor) {
            (0, 0) => format!(
                "npm: 0.0.x band — {from} -> {to} crosses a patch boundary (breaking-by-spec); \
                 widens `^{from}` -> `^{to}`"
            ),
            (0, _) if from_v.minor != to_v.minor => format!(
                "npm: 0.x band — {from} -> {to} crosses minor={}→{} (breaking-by-spec); \
                 widens `^{from}` -> `^{to}`",
                from_v.minor, to_v.minor
            ),
            _ if from_v.major != to_v.major => format!(
                "npm: 1.0+ band — {from} -> {to} crosses major={}→{} (breaking-by-spec); \
                 widens `^{from}` -> `^{to}`",
                from_v.major, to_v.major
            ),
            _ => format!(
                "npm: {from} -> {to} crosses a caret-compat group boundary; widens \
                 `^{from}` -> `^{to}` and merits review"
            ),
        };
        BumpExplanation {
            summary,
            rule: rule.into(),
            inputs,
            decision: "breaking".into(),
        }
    }
}

/// Build a `LockfileOnly` explanation — the new version satisfies the
/// existing constraint and only `package-lock.json` / `pnpm-lock.yaml`
/// / `yarn.lock` changes.
pub(crate) fn explain_npm_lockfile_only_bump(
    from: &str,
    to: &str,
    constraint: Option<&str>,
) -> crate::model::BumpExplanation {
    use crate::model::BumpExplanation;
    use std::collections::BTreeMap;

    let mut inputs = BTreeMap::new();
    inputs.insert("from".into(), from.to_string());
    inputs.insert("to".into(), to.to_string());
    if let Some(c) = constraint {
        inputs.insert("constraint".into(), c.to_string());
    }
    let summary = match constraint {
        Some(c) => format!(
            "npm: new version {to} satisfies the existing constraint `{c}`; only the \
             lockfile changes (no manifest edit required)"
        ),
        None => format!(
            "npm: new version {to} satisfies the existing constraint; only the lockfile \
             changes (no manifest edit required)"
        ),
    };
    BumpExplanation {
        summary,
        rule: "npm:lockfile-within-constraint".into(),
        inputs,
        decision: "lockfile-only".into(),
    }
}

/// Filter proposals down to direct deps declared in `package.json` (root
/// + any workspace members). Drops transitive entries that `npm
/// outdated` surfaces but the applier can't widen.
pub(crate) fn filter_to_direct_deps(
    proposals: Vec<Proposal>,
    direct: &BTreeSet<String>,
) -> Vec<Proposal> {
    proposals
        .into_iter()
        .filter(|p| direct.contains(&p.subject))
        .collect()
}

fn run_npm_proposer(
    flavor: NpmFlavor,
    repo: &Path,
    manifest_paths: &[PathBuf],
) -> Result<Vec<Proposal>> {
    let bin = npm_binary_name(flavor);
    if bin.is_empty() {
        return Ok(Vec::new());
    }
    // Yarn berry has no built-in `outdated` and goes through a
    // dedicated proposer that walks direct deps + queries `yarn npm
    // info` per dep. Route here instead of falling through the
    // outdated-subprocess path below.
    if matches!(flavor, NpmFlavor::YarnBerry) {
        return propose_berry_updates(repo, manifest_paths);
    }
    let args: &[&str] = match flavor {
        // `npm outdated` from a workspace root enumerates workspace
        // member deps via npm 7+ flattening; no recursive flag needed.
        NpmFlavor::Npm => &["outdated", "--json"],
        // `pnpm outdated` from a workspace root reports ONLY the root
        // package's deps. `-r` (recursive) enumerates every workspace
        // member's outdated entries; without it, monorepos look empty.
        NpmFlavor::Pnpm => &["outdated", "-r", "--format=json"],
        // Yarn 1 has no `-r` analogue and doesn't ship native
        // workspaces in the same shape; yarn 1's `outdated --json`
        // surfaces the project's flat dep set.
        NpmFlavor::Yarn => &["outdated", "--json"],
        // Routed above.
        NpmFlavor::YarnBerry => unreachable!("YarnBerry handled by propose_berry_updates"),
    };

    let mut cmd = std::process::Command::new(bin);
    cmd.args(args).current_dir(repo);
    let run = run_with_timeout(cmd, std::time::Duration::from_secs(120))
        .map_err(|source| map_npm_spawn_io(source, bin, flavor, repo))?;
    let RunResult::Completed { status, stdout, .. } = run else {
        return Err(Error::other(format!(
            "{bin} outdated timed out against `{}`",
            repo.display()
        )));
    };
    // npm outdated exits non-zero when packages are outdated; we ignore
    // the exit code and rely on parsing.
    let _ = status;
    let stdout_str = String::from_utf8_lossy(&stdout);

    let mut rows = match flavor {
        NpmFlavor::Yarn => parse_yarn1_outdated_output(&stdout_str)?,
        NpmFlavor::YarnBerry => {
            unreachable!("YarnBerry routed through propose_berry_updates")
        }
        _ => parse_npm_outdated_output(&stdout_str)?,
    };
    // When `node_modules` isn't materialized, `npm outdated` omits the
    // `current` field. Fall back to the package-lock.json's resolved
    // version so assay can still surface proposals without forcing the
    // operator to run `npm install` first. (yarn1 typically reports
    // `current` directly, but the backfill is a no-op for already-set
    // rows.)
    if matches!(flavor, NpmFlavor::Npm) {
        backfill_current_from_lockfile(repo, &mut rows)?;
    }
    let proposals = build_npm_proposals(&rows, manifest_paths);
    let direct = collect_direct_dep_names(repo)?;
    Ok(filter_to_direct_deps(proposals, &direct))
}

/// Read each `node_modules/<name>` entry from a `package-lock.json` v3
/// `packages` map. Returns a `name -> version` lookup for use when
/// `npm outdated` omits the `current` field (no installed
/// node_modules).
pub(crate) fn read_lockfile_versions(repo: &Path) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let lockfile = repo.join("package-lock.json");
    if !lockfile.is_file() {
        return Ok(out);
    }
    let text = std::fs::read_to_string(&lockfile).map_err(|source| Error::Io {
        path: lockfile.clone(),
        source,
    })?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| Error::other(format!("package-lock.json parse: {e}")))?;
    // Modern lockfile shape (v2/v3): `packages` map keyed by
    // `"node_modules/<name>"`. Nested deps may have keys like
    // `"node_modules/a/node_modules/b"` — those are transitive copies
    // and we want the *top-level* resolution. The simplest pick: take
    // the first occurrence of each `<name>`. v1 lockfiles use a
    // `dependencies` tree which we skip — modern projects (npm 7+)
    // produce v2/v3 by default.
    if let Some(packages) = value.get("packages").and_then(|v| v.as_object()) {
        for (key, entry) in packages {
            let Some(rest) = key.strip_prefix("node_modules/") else {
                continue;
            };
            // Skip nested deps; only top-level `node_modules/<name>`.
            if rest.contains("/node_modules/") {
                continue;
            }
            let Some(version) = entry.get("version").and_then(|v| v.as_str()) else {
                continue;
            };
            out.entry(rest.to_string())
                .or_insert_with(|| version.to_string());
        }
    }
    Ok(out)
}

fn backfill_current_from_lockfile(repo: &Path, rows: &mut [NpmOutdatedRow]) -> Result<()> {
    let needs_backfill = rows.iter().any(|r| r.current.is_none());
    if !needs_backfill {
        return Ok(());
    }
    let lockfile = read_lockfile_versions(repo)?;
    for row in rows.iter_mut() {
        if row.current.is_none()
            && let Some(v) = lockfile.get(&row.name)
        {
            row.current = Some(v.clone());
        }
    }
    Ok(())
}

/// Read every dep name declared in `package.json`'s `dependencies`,
/// `devDependencies`, `peerDependencies`, and `optionalDependencies`.
/// Workspace members are walked via [`detect_workspace_members`] so npm
/// 7+ workspace globs (`packages/*`) and pnpm-workspace.yaml entries are
/// all expanded before scanning for declared deps.
pub(crate) fn collect_direct_dep_names(repo: &Path) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    let root_pkg = repo.join("package.json");
    if root_pkg.is_file() {
        let root_text = std::fs::read_to_string(&root_pkg).map_err(|source| Error::Io {
            path: root_pkg.clone(),
            source,
        })?;
        let root_value: serde_json::Value = serde_json::from_str(&root_text)
            .map_err(|e| Error::other(format!("package.json parse: {e}")))?;
        extend_dep_names(&root_value, &mut names);
    }
    for member in detect_workspace_members(repo)? {
        let member_pkg = repo.join(&member.relative_path).join("package.json");
        if !member_pkg.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&member_pkg).map_err(|source| Error::Io {
            path: member_pkg.clone(),
            source,
        })?;
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
            extend_dep_names(&value, &mut names);
        }
    }
    Ok(names)
}

fn extend_dep_names(pkg: &serde_json::Value, names: &mut BTreeSet<String>) {
    for field in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        if let Some(obj) = pkg.get(field).and_then(|v| v.as_object()) {
            for key in obj.keys() {
                names.insert(key.clone());
            }
        }
    }
}

/// Like [`collect_direct_dep_names`], but pairs each name with its
/// declared constraint string from package.json. Used by the berry
/// proposer to know what range each direct dep is pinned to so the
/// applier can preserve operator-chosen prefixes. Workspace-member
/// deps merge into the result; later-walked members override earlier
/// ones on key collision (rare in practice — a workspace shouldn't
/// declare the same dep at two different constraints across members).
pub(crate) fn collect_direct_deps_with_constraints(
    repo: &Path,
) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let root_pkg = repo.join("package.json");
    if root_pkg.is_file() {
        let text = std::fs::read_to_string(&root_pkg).map_err(|source| Error::Io {
            path: root_pkg.clone(),
            source,
        })?;
        let value: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| Error::other(format!("package.json parse: {e}")))?;
        extend_dep_constraints(&value, &mut out);
    }
    for member in detect_workspace_members(repo)? {
        let member_pkg = repo.join(&member.relative_path).join("package.json");
        if !member_pkg.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&member_pkg).map_err(|source| Error::Io {
            path: member_pkg.clone(),
            source,
        })?;
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
            extend_dep_constraints(&value, &mut out);
        }
    }
    Ok(out)
}

fn extend_dep_constraints(pkg: &serde_json::Value, out: &mut BTreeMap<String, String>) {
    for field in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        if let Some(obj) = pkg.get(field).and_then(|v| v.as_object()) {
            for (key, value) in obj {
                if let Some(s) = value.as_str() {
                    out.insert(key.clone(), s.to_string());
                }
            }
        }
    }
}

/// Parse a yarn berry `yarn.lock` file (YAML format with descriptor
/// blocks) and return a `subject -> installed_version` map.
///
/// Berry yarn.lock entries look like:
/// ```yaml
/// "lodash@npm:^4.17.21":
///   version: 4.17.21
///   resolution: "lodash@npm:4.17.21"
/// ```
/// Multiple descriptors may share a block via comma-separation. The
/// `__metadata:` header is skipped. Entries with no top-level `version`
/// field (e.g. workspace-protocol entries) are skipped — we can't
/// compare against a "current" version for them.
pub(crate) fn parse_berry_lockfile(text: &str) -> Result<BTreeMap<String, String>> {
    let value: serde_yml::Value = serde_yml::from_str(text)
        .map_err(|e| Error::other(format!("yarn.lock (berry) parse: {e}")))?;
    let mut out = BTreeMap::new();
    let Some(top) = value.as_mapping() else {
        return Ok(out);
    };
    for (key, val) in top {
        let Some(descriptor_blob) = key.as_str() else {
            continue;
        };
        if descriptor_blob == "__metadata" {
            continue;
        }
        let Some(version) = val
            .as_mapping()
            .and_then(|m| m.get(serde_yml::Value::String("version".into())))
            .and_then(|v| v.as_str())
        else {
            continue;
        };
        // The blob may carry multiple comma-separated descriptors
        // pointing at the same resolution. Yield one map entry per
        // distinct package name; if a name appears twice across
        // blobs (rare — same dep at two pinned versions) the last
        // wins, matching how berry itself surfaces the package.
        for descriptor in descriptor_blob.split(',').map(str::trim) {
            if descriptor.is_empty() {
                continue;
            }
            if let Some(name) = parse_berry_descriptor_name(descriptor) {
                out.insert(name, version.to_string());
            }
        }
    }
    Ok(out)
}

/// Extract just the package name from a berry descriptor.
///
/// Berry descriptors look like `<name>@<protocol>:<range>`, e.g.
/// `lodash@npm:^4.17.21` or `@types/node@npm:^20.10.0`. Scoped names
/// start with `@` and the relevant `@` separator is the SECOND `@`.
/// Workspace-protocol entries (`my-pkg@workspace:^`) parse the same
/// way; the caller decides whether to use them.
fn parse_berry_descriptor_name(descriptor: &str) -> Option<String> {
    let trimmed = descriptor.trim().trim_matches('"');
    // Scoped names: find the second `@` (the one preceded by a
    // non-`@` char).
    if let Some(rest) = trimmed.strip_prefix('@') {
        let at = rest.find('@')?;
        Some(format!("@{}", &rest[..at]))
    } else {
        let at = trimmed.find('@')?;
        Some(trimmed[..at].to_string())
    }
}

/// Query `yarn npm info <pkg> --json` for `pkg`'s latest registry
/// version. Returns the version string from `dist-tags.latest`, or
/// `None` when the query fails, the package isn't on the registry,
/// or the response shape doesn't carry the expected fields.
///
/// Berry projects typically pin a specific yarn version via
/// `packageManager` in package.json and rely on
/// [corepack](https://nodejs.org/api/corepack.html) to dispatch the
/// `yarn` command to that version. The `yarn` binary on PATH may
/// itself be yarn1 (from a global `npm install -g yarn`) — that
/// binary rejects the berry-specific `yarn npm info` subcommand. To
/// support both shapes we try `corepack yarn ...` first (works on
/// every modern Node), then fall back to direct `yarn ...` for
/// environments where corepack isn't installed but the on-PATH
/// `yarn` is already a berry-capable shim.
///
/// Errors are NOT bubbled — a single registry hiccup shouldn't tank
/// the whole proposer run.
fn query_berry_latest_version(repo: &Path, pkg: &str) -> Option<String> {
    let yarn_bin = npm_binary_name(NpmFlavor::YarnBerry);
    // On Windows, npm-family binaries ship as `.cmd` shims around
    // node scripts; `Command::new` resolves only `.exe` automatically.
    // Same applies to corepack.
    let corepack_bin = if cfg!(windows) {
        "corepack.cmd"
    } else {
        "corepack"
    };
    let attempts: &[(&str, &[&str])] = &[
        // Corepack-mediated path. `corepack yarn ...` honours
        // package.json's `packageManager` field and reliably runs
        // berry even when the global `yarn` shim is yarn1.
        (corepack_bin, &["yarn", "npm", "info", pkg, "--json"]),
        // Direct path. Works when `yarn` itself is a berry binary
        // (e.g. when the project pins berry via `.yarn/releases/...`
        // and the shim PATH integration is set up correctly).
        (yarn_bin, &["npm", "info", pkg, "--json"]),
    ];
    for (bin, args) in attempts {
        let mut cmd = std::process::Command::new(bin);
        cmd.args(*args).current_dir(repo);
        let run = match run_with_timeout(cmd, std::time::Duration::from_secs(30)) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let RunResult::Completed { status, stdout, .. } = run else {
            continue;
        };
        if !status.success() {
            continue;
        }
        let text = String::from_utf8_lossy(&stdout);
        // berry's stdout may be a single JSON object or one-line-per-
        // package JSON streamed by `npm info`. Try whole-string parse
        // first, then fall back to the first parseable line.
        let trimmed = text.trim();
        let parsed = serde_json::from_str::<serde_json::Value>(trimmed)
            .ok()
            .or_else(|| {
                text.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .find_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            });
        let Some(value) = parsed else {
            continue;
        };
        if let Some(latest) = value
            .get("dist-tags")
            .and_then(|v| v.get("latest"))
            .and_then(|v| v.as_str())
        {
            return Some(latest.to_string());
        }
        if let Some(version) = value.get("version").and_then(|v| v.as_str()) {
            return Some(version.to_string());
        }
    }
    None
}

/// Yarn berry proposer — walks direct deps from package.json (root +
/// workspace members), queries `yarn npm info` for each, compares
/// against the berry yarn.lock's installed version, and emits one
/// proposal per (newer-version-available) dep.
///
/// Berry has no built-in `outdated` command in core (it was removed
/// in v2; a third-party plugin exists but isn't shipped by default),
/// so this per-dep walk is the canonical reliable path. Per-dep
/// registry queries are slow (N subprocesses per project) but
/// deterministic and don't require a plugin install.
fn propose_berry_updates(repo: &Path, manifest_paths: &[PathBuf]) -> Result<Vec<Proposal>> {
    let direct = collect_direct_deps_with_constraints(repo)?;
    if direct.is_empty() {
        return Ok(Vec::new());
    }
    let lockfile_path = repo.join("yarn.lock");
    let installed = match std::fs::read_to_string(&lockfile_path) {
        Ok(text) => parse_berry_lockfile(&text)?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
        Err(err) => {
            return Err(Error::Io {
                path: lockfile_path,
                source: err,
            });
        }
    };
    let mut rows: Vec<NpmOutdatedRow> = Vec::new();
    let mut queried = 0usize;
    let mut succeeded = 0usize;
    for name in direct.keys() {
        queried += 1;
        let current = installed.get(name).cloned();
        let Some(latest) = query_berry_latest_version(repo, name) else {
            continue;
        };
        succeeded += 1;
        // Skip when no current version is known (dep declared but
        // never installed) or when the lockfile already matches the
        // latest registry version.
        let Some(current) = current else { continue };
        if current == latest {
            continue;
        }
        // Berry has no `wanted` signal (the in-constraint maximum
        // npm/pnpm both expose). Setting `wanted = current` forces
        // [`build_npm_proposals`] to route through
        // [`classify_npm_bump`] rather than collapsing every bump
        // to `LockfileOnly`. That keeps the tier classification
        // honest: an exact-pin constraint that doesn't satisfy
        // `latest` produces a Compatible/Breaking proposal that
        // requires manifest editing, while a caret-anchored
        // constraint that does satisfy `latest` will be re-tiered
        // to LockfileOnly by a future enhancement that inspects
        // the constraint string. For now we err on the side of
        // requiring the operator to review constraint edits.
        rows.push(NpmOutdatedRow {
            name: name.clone(),
            current: Some(current.clone()),
            wanted: current,
            latest,
        });
    }
    if queried > 0 && succeeded == 0 {
        eprintln!(
            "[npm:berry] queried {queried} direct dep(s) via `corepack yarn npm info` and `yarn npm info`; \
             neither pathway returned a usable registry response. Install corepack (or a berry-capable \
             yarn binary on PATH) so assay can resolve registry versions for this project.",
        );
    }
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(build_npm_proposals(&rows, manifest_paths))
}

/// Apply an npm proposal:
///
/// - **LockfileOnly:** install the explicit target version with
///   `--no-save --package-lock-only`. This bumps only the lockfile
///   (package.json's constraint is untouched). Plain
///   `npm install --package-lock-only` would be a no-op when the
///   lockfile is already in sync with package.json — we need to push
///   the resolution to the specific `to` version.
/// - **Compatible / Breaking:** widen the constraint in `package.json`
///   first, then run a plain `install --package-lock-only` so the
///   lockfile picks up the new constraint.
fn apply_npm_proposal(flavor: NpmFlavor, proposal: &Proposal, tree_path: &Path) -> Result<()> {
    if matches!(proposal.bump_tier, BumpTier::LockfileOnly) {
        // Aliased deps (`"my-lodash": "npm:lodash@4.17.21"`) need the
        // alias spec re-emitted on the install command — otherwise npm
        // tries to fetch a registry package named after the local alias
        // key (`my-lodash`) and fails.
        let install_version = resolve_install_version(tree_path, &proposal.subject, &proposal.to)?;
        return run_install_pinned(flavor, &proposal.subject, &install_version, tree_path);
    }
    let modified = update_package_json_constraint(tree_path, &proposal.subject, &proposal.to)?;
    if modified.is_empty() {
        return Err(Error::other(format!(
            "expected to widen the constraint for `{}` in {} but no package.json had a matching dep entry",
            proposal.subject,
            tree_path.display(),
        )));
    }
    run_install_lockfile_only(flavor, tree_path)
}

/// Install a specific `<name>@<version>` into the lockfile while
/// preserving `package.json`'s original constraint. Used for
/// LockfileOnly bumps.
///
/// Implementation: snapshot `package.json` text → install WITH
/// `--save-exact` (forces npm to actually move to the requested
/// version) → restore the snapshotted `package.json` bytes. The
/// lockfile keeps the bump; the manifest is byte-identical to where
/// it started.
///
/// Why not `--no-save`? npm's `--no-save` flag puts the resolver in a
/// "minimum-change" mode: if the existing lockfile version already
/// satisfies the manifest constraint, npm decides the lockfile is
/// "current" and doesn't bump even when an explicit `pkg@version` is
/// passed. The save-and-restore wrapper sidesteps that by giving npm
/// permission to mutate package.json (which forces the lockfile
/// update) and then taking that mutation back.
fn run_install_pinned(
    flavor: NpmFlavor,
    name: &str,
    version: &str,
    tree_path: &Path,
) -> Result<()> {
    let pinned = format!("{name}@{version}");
    let args: Vec<&str> = match flavor {
        NpmFlavor::Npm => vec![
            "install",
            &pinned,
            "--save-exact",
            "--no-audit",
            "--no-fund",
        ],
        NpmFlavor::Pnpm => vec!["add", &pinned, "--save-exact"],
        // yarn1: `yarn upgrade pkg@version --exact` bumps both
        // package.json + yarn.lock; same snapshot/restore wrapper
        // around it ensures LockfileOnly intent.
        NpmFlavor::Yarn => vec!["upgrade", &pinned, "--exact"],
        // yarn berry: `yarn up <pkg>@<ver>` bumps both
        // package.json + yarn.lock. Berry's `up` has no `--exact`
        // flag — exactness comes from passing a fully-specified
        // version (no `^`/`~`); the snapshot/restore wrapper still
        // applies for LockfileOnly intent.
        NpmFlavor::YarnBerry => vec!["up", &pinned],
    };
    let package_json = tree_path.join("package.json");
    let snapshot = std::fs::read(&package_json).map_err(|source| Error::Io {
        path: package_json.clone(),
        source,
    })?;
    let (cmd, bin_label) = build_npm_install_command(flavor, &args, tree_path);
    let install_result = run_install_with_timeout(cmd, bin_label, tree_path);
    // Restore package.json verbatim even if install failed — leaves the
    // sandbox in a sane state for diagnostics. The Result from install
    // is still propagated.
    let _ = std::fs::write(&package_json, &snapshot);
    install_result
}

/// Refresh the lockfile after a manifest constraint edit. Same
/// rationale for dropping `--package-lock-only` as in
/// [`run_install_pinned`].
fn run_install_lockfile_only(flavor: NpmFlavor, tree_path: &Path) -> Result<()> {
    let args: &[&str] = match flavor {
        NpmFlavor::Npm => &["install", "--no-audit", "--no-fund"],
        NpmFlavor::Pnpm => &["install"],
        // yarn1: `yarn install` refreshes yarn.lock against the
        // freshly-edited package.json.
        NpmFlavor::Yarn => &["install"],
        // yarn berry: same `yarn install` refresh shape.
        NpmFlavor::YarnBerry => &["install"],
    };
    let (cmd, bin_label) = build_npm_install_command(flavor, args, tree_path);
    run_install_with_timeout(cmd, bin_label, tree_path)
}

/// Build the `std::process::Command` for an npm-family install. For
/// `YarnBerry` this routes through `corepack yarn ...` so the project's
/// `packageManager` field selects the right yarn version — invoking the
/// global `yarn` binary directly fails when it's yarn1 but the project
/// pins berry. For other flavors it returns the binary directly.
///
/// Returns `(Command, bin_label)` where `bin_label` is the string used
/// in error messages (e.g. `"corepack yarn"` for berry,
/// `"yarn.cmd"` for yarn1).
fn build_npm_install_command(
    flavor: NpmFlavor,
    args: &[&str],
    tree_path: &Path,
) -> (std::process::Command, &'static str) {
    match flavor {
        NpmFlavor::YarnBerry => {
            let corepack_bin = if cfg!(windows) {
                "corepack.cmd"
            } else {
                "corepack"
            };
            let mut cmd = std::process::Command::new(corepack_bin);
            cmd.arg("yarn").args(args).current_dir(tree_path);
            (cmd, "corepack yarn")
        }
        _ => {
            let bin = npm_binary_name(flavor);
            let mut cmd = std::process::Command::new(bin);
            cmd.args(args).current_dir(tree_path);
            (cmd, bin)
        }
    }
}

fn run_install_with_timeout(cmd: std::process::Command, bin: &str, tree_path: &Path) -> Result<()> {
    // Recover the flavor from the binary name so a missing-binary
    // error from the install path produces the same flavor-aware
    // message as the proposer path. Fallback to npm if we can't
    // recognize it (defensive — bin always comes from npm_binary_name).
    let flavor = flavor_from_binary_name(bin).unwrap_or(NpmFlavor::Npm);
    let run = run_with_timeout(cmd, std::time::Duration::from_secs(300))
        .map_err(|source| map_npm_spawn_io(source, bin, flavor, tree_path))?;
    let RunResult::Completed {
        status,
        stdout,
        stderr,
        ..
    } = run
    else {
        return Err(Error::other(format!(
            "{bin} install timed out against `{}`",
            tree_path.display()
        )));
    };
    if !status.success() {
        return Err(Error::other(format!(
            "{bin} install failed: exit={:?}\nstdout=\n{}\nstderr=\n{}",
            status.code(),
            String::from_utf8_lossy(&stdout).trim(),
            String::from_utf8_lossy(&stderr).trim(),
        )));
    }
    Ok(())
}

/// Format-best-effort `package.json` constraint editor. Reads JSON via
/// `serde_json::Value` and writes back with 2-space indent (npm/pnpm's
/// own convention when they edit package.json on `install --save`).
///
/// Walks `dependencies`, `devDependencies`, `peerDependencies`, and
/// `optionalDependencies` — first hit wins. Constraint widening preserves
/// the operator's caret/tilde prefix when present:
/// - `"^1.0.0"` → `"^1.5.0"` (caret preserved)
/// - `"~1.0.0"` → `"~1.5.0"` (tilde preserved)
/// - `"1.0.0"` → `"^1.5.0"` (bare bumps gain a caret — npm's default
///   for `npm install --save`)
pub(crate) fn update_package_json_constraint(
    tree_path: &Path,
    name: &str,
    new_version: &str,
) -> Result<Vec<PathBuf>> {
    let mut modified: Vec<PathBuf> = Vec::new();
    let root_pkg = tree_path.join("package.json");
    if try_edit_package_json(&root_pkg, name, new_version)? {
        modified.push(PathBuf::from("package.json"));
    }
    for member in detect_workspace_members(tree_path)? {
        let member_pkg = tree_path.join(&member.relative_path).join("package.json");
        if !member_pkg.is_file() {
            continue;
        }
        if try_edit_package_json(&member_pkg, name, new_version)? {
            modified.push(member.relative_path.join("package.json"));
        }
    }
    modified.sort();
    modified.dedup();
    Ok(modified)
}

/// A workspace member discovered under `tree_path`.
///
/// `relative_path` is the workspace-relative directory holding the
/// member's `package.json`. `name` is whatever the member's
/// `package.json` declares (used as the [`ConsumerId`] in reports).
#[derive(Debug, Clone)]
pub(crate) struct WorkspaceMember {
    pub relative_path: PathBuf,
    pub name: String,
}

/// Discover npm/yarn/pnpm workspace members under `tree_path`.
///
/// Reads `workspaces` from the root `package.json` (either an array or
/// `{ packages: [...] }`) for npm/yarn, AND `packages:` from
/// `pnpm-workspace.yaml` for pnpm. Both sources are unioned — projects
/// rarely have both, but if they do we treat them as a combined set.
///
/// Glob patterns (`packages/*`, `apps/*-server`) are expanded relative
/// to `tree_path`. Each resolved directory is included only if it
/// contains a `package.json` with a parseable `name`. Members are
/// sorted by relative path and deduped.
///
/// Returns an empty Vec when no workspace declaration exists (the
/// single-project case).
pub(crate) fn detect_workspace_members(tree_path: &Path) -> Result<Vec<WorkspaceMember>> {
    // Canonicalize so `--repo .` works: the glob walker yields paths
    // relative to CWD, and a `Path::strip_prefix(".")` against an
    // already-relative match like `packages/alpha` fails. Resolving the
    // tree to absolute makes the prefix-strip consistent regardless of
    // how the operator invoked assay.
    let tree_path_owned = match std::path::absolute(tree_path) {
        Ok(p) => p,
        Err(_) => tree_path.to_path_buf(),
    };
    let tree_path = tree_path_owned.as_path();
    let mut patterns: BTreeSet<String> = BTreeSet::new();
    let root_pkg = tree_path.join("package.json");
    if let Ok(text) = std::fs::read_to_string(&root_pkg)
        && let Ok(root_value) = serde_json::from_str::<serde_json::Value>(&text)
        && let Some(ws) = root_value.get("workspaces")
    {
        let entries: Vec<String> = if let Some(arr) = ws.as_array() {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        } else if let Some(obj) = ws.as_object() {
            obj.get("packages")
                .and_then(|p| p.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        patterns.extend(entries);
    }
    let pnpm_ws = tree_path.join("pnpm-workspace.yaml");
    if let Ok(text) = std::fs::read_to_string(&pnpm_ws)
        && let Ok(value) = serde_yml::from_str::<serde_yml::Value>(&text)
        && let Some(packages) = value.get("packages").and_then(|p| p.as_sequence())
    {
        for entry in packages {
            if let Some(s) = entry.as_str() {
                patterns.insert(s.to_string());
            }
        }
    }

    // Split positive patterns from negation patterns. pnpm honors
    // `!packages/private` as an exclusion against the resolved member
    // set. Negations apply AFTER positive expansion; subtraction matches
    // by exact path or glob.
    let (positive_patterns, negation_patterns): (Vec<&String>, Vec<&String>) =
        patterns.iter().partition(|p| !p.starts_with('!'));
    let mut resolved_dirs: BTreeSet<PathBuf> = BTreeSet::new();
    for pattern in &positive_patterns {
        if pattern.contains('*') || pattern.contains('?') || pattern.contains('[') {
            let absolute_pattern = tree_path.join(pattern);
            let pattern_str = match absolute_pattern.to_str() {
                Some(s) => s,
                None => continue,
            };
            // The `glob` crate's pattern parser interprets `\` as an
            // escape character on every platform, so Windows-style
            // backslash separators (`C:\repo\packages\*`) produce zero
            // matches. Normalize to forward slashes — `Path::strip_prefix`
            // still works on the matched results because Rust's std
            // accepts both separators on Windows.
            let normalized = pattern_str.replace('\\', "/");
            if let Ok(walker) = glob::glob(&normalized) {
                for entry in walker.flatten() {
                    if entry.is_dir()
                        && entry.join("package.json").is_file()
                        && let Ok(rel) = entry.strip_prefix(tree_path)
                    {
                        resolved_dirs.insert(rel.to_path_buf());
                    }
                }
            }
        } else {
            let candidate = tree_path.join(pattern);
            if candidate.is_dir() && candidate.join("package.json").is_file() {
                resolved_dirs.insert(PathBuf::from(pattern.as_str()));
            }
        }
    }

    // Apply negation: drop any resolved dir that matches a `!<pattern>`
    // entry (literal path or glob). pnpm's spec says negations win
    // regardless of declaration order.
    for negation in &negation_patterns {
        let pattern_body = &negation[1..]; // strip the leading `!`
        if pattern_body.contains('*') || pattern_body.contains('?') || pattern_body.contains('[') {
            let absolute_pattern = tree_path.join(pattern_body);
            let Some(pattern_str) = absolute_pattern.to_str() else {
                continue;
            };
            let normalized = pattern_str.replace('\\', "/");
            if let Ok(walker) = glob::glob(&normalized) {
                for entry in walker.flatten() {
                    if let Ok(rel) = entry.strip_prefix(tree_path) {
                        resolved_dirs.remove(rel);
                    }
                }
            }
        } else {
            resolved_dirs.remove(Path::new(pattern_body));
        }
    }

    let mut out: Vec<WorkspaceMember> = Vec::new();
    for rel in resolved_dirs {
        let pkg_path = tree_path.join(&rel).join("package.json");
        let Ok(text) = std::fs::read_to_string(&pkg_path) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        let Some(name) = value.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        out.push(WorkspaceMember {
            relative_path: rel,
            name: name.to_string(),
        });
    }
    out.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    Ok(out)
}

/// Return the workspace members that declare `proposal.subject` as a
/// direct dependency.
///
/// Mirrors cargo's `affected_consumers` semantics: a member is a
/// "consumer" if its `package.json`'s `dependencies` /
/// `devDependencies` / `peerDependencies` / `optionalDependencies`
/// lists the bumped package. Self-references are excluded (a member
/// whose own `name` matches `proposal.subject` is the bumped package,
/// not a consumer).
///
/// Returns an empty Vec when no workspace declaration exists or no
/// member declares the dep — the Reporter collapses to a flat single-
/// project view in that case.
fn resolve_npm_consumers(proposal: &Proposal, tree: &Path) -> Result<Vec<ConsumerId>> {
    let mut consumers: Vec<ConsumerId> = Vec::new();
    for member in detect_workspace_members(tree)? {
        if member.name == proposal.subject {
            continue;
        }
        let pkg_path = tree.join(&member.relative_path).join("package.json");
        if package_json_declares(&pkg_path, &proposal.subject)? {
            consumers.push(member.name.clone());
        }
    }
    // Augment with peer-dep declarers from node_modules. For a
    // library that declares `peerDependencies: { "@angular/core":
    // ">=21" }`, an `@angular/core` bump may shift the minimum peer
    // range — that's the "blast radius" data the operator needs.
    // The dogfood (slate, aegis, wildmason.dev) flagged this as the
    // biggest npm `affected_consumers` gap. Failures are silent
    // (best-effort) — proposers don't crash because node_modules
    // happens to be partially installed.
    for peer in find_peer_dep_consumers(tree, &proposal.subject) {
        if peer == proposal.subject {
            continue;
        }
        if !consumers.iter().any(|c| c == &peer) {
            consumers.push(peer);
        }
    }
    consumers.sort();
    Ok(consumers)
}

/// Walk `node_modules/*/package.json` (and the scoped variant
/// `node_modules/@*/*/package.json`) looking for declarations of
/// `subject` in the `peerDependencies` block. Returns the list of
/// package names that declare it. Best-effort — IO errors are
/// swallowed since the proposer should still ship results when
/// node_modules is in a half-installed state.
///
/// Handles three layouts:
/// - npm/yarn1 flat hoisted: `node_modules/foo/`
/// - scoped: `node_modules/@scope/foo/`
/// - pnpm virtual store: `node_modules/.pnpm/<id>/node_modules/<pkg>/`
///
/// pnpm-style monorepos (the dominant flavor in modern Wildmason
/// projects) put the real install at `.pnpm/<pkg>@<ver>/node_modules/`
/// while the top-level `node_modules/` only contains symlinks to
/// declared deps. Without the virtual-store walk, peer-dep coverage
/// only finds direct first-party consumers — every transitive
/// declarer that pnpm hoists into its store is invisible.
///
/// Names are deduplicated: the same library can appear at multiple
/// versions or with multiple peer-resolution suffixes (e.g.
/// `@angular+cdk@21.0.0_@angular+core@21.0.0`) and should still be
/// reported once.
fn find_peer_dep_consumers(tree: &Path, subject: &str) -> Vec<String> {
    let node_modules = tree.join("node_modules");
    if !node_modules.is_dir() {
        return Vec::new();
    }
    let mut out: Vec<String> = Vec::new();
    walk_flat_node_modules(&node_modules, subject, &mut out);
    let pnpm_store = node_modules.join(".pnpm");
    if pnpm_store.is_dir() {
        walk_pnpm_virtual_store(&pnpm_store, subject, &mut out);
    }
    out.sort();
    out.dedup();
    out
}

/// Walk a flat `node_modules`-style directory looking for
/// `peerDependencies[subject]` declarations. Handles both unscoped
/// (`<root>/foo/`) and scoped (`<root>/@scope/foo/`) entries. Skips
/// dotted entries like `.bin`, `.cache`, and `.pnpm` (the virtual
/// store has its own walker). Pushes matches into `out` without
/// deduplication; the caller is responsible for sort+dedup.
fn walk_flat_node_modules(root: &Path, subject: &str, out: &mut Vec<String>) {
    let entries = match std::fs::read_dir(root) {
        Ok(iter) => iter,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = match entry.file_name().into_string() {
            Ok(s) => s,
            Err(_) => continue,
        };
        if name.starts_with('.') {
            continue;
        }
        if name.starts_with('@') {
            let scope_entries = match std::fs::read_dir(&path) {
                Ok(iter) => iter,
                Err(_) => continue,
            };
            for sub in scope_entries.flatten() {
                let sub_name = match sub.file_name().into_string() {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let full = format!("{name}/{sub_name}");
                check_peer_dep(&sub.path(), subject, &full, out);
            }
        } else {
            check_peer_dep(&path, subject, &name, out);
        }
    }
}

/// Walk pnpm's virtual store. Each entry under `.pnpm/` is named
/// `<pkg>@<ver>(_<peer-resolution>)?` (with scoped slashes escaped
/// to `+`) and contains a `node_modules/` directory holding the
/// hoisted install plus any peer-linked siblings. We delegate each
/// `<entry>/node_modules/` to [`walk_flat_node_modules`] — the
/// layout inside is structurally identical to a flat hoisted tree.
/// Best-effort on errors; partial pnpm installs do not crash the
/// proposer.
fn walk_pnpm_virtual_store(store: &Path, subject: &str, out: &mut Vec<String>) {
    let entries = match std::fs::read_dir(store) {
        Ok(iter) => iter,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let inner_nm = path.join("node_modules");
        if !inner_nm.is_dir() {
            continue;
        }
        walk_flat_node_modules(&inner_nm, subject, out);
    }
}

/// Parse `<pkg_dir>/package.json` and append `pkg_name` to `out` if
/// the manifest declares `subject` in its `peerDependencies` block.
/// Silent on any IO / parse failure — peer-dep population is
/// advisory.
fn check_peer_dep(pkg_dir: &Path, subject: &str, pkg_name: &str, out: &mut Vec<String>) {
    let pkg_json = pkg_dir.join("package.json");
    let text = match std::fs::read_to_string(&pkg_json) {
        Ok(t) => t,
        Err(_) => return,
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return;
    };
    if let Some(obj) = value.get("peerDependencies").and_then(|v| v.as_object())
        && obj.contains_key(subject)
    {
        out.push(pkg_name.to_string());
    }
}

fn package_json_declares(pkg_path: &Path, name: &str) -> Result<bool> {
    let text = match std::fs::read_to_string(pkg_path) {
        Ok(t) => t,
        Err(_) => return Ok(false),
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Ok(false);
    };
    for field in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        if let Some(obj) = value.get(field).and_then(|v| v.as_object())
            && obj.contains_key(name)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn try_edit_package_json(path: &Path, name: &str, new_version: &str) -> Result<bool> {
    let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| Error::other(format!("{}: {e}", path.display())))?;
    let mut edited = false;
    for field in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        let Some(obj) = value.get_mut(field).and_then(|v| v.as_object_mut()) else {
            continue;
        };
        let Some(existing) = obj.get_mut(name) else {
            continue;
        };
        let Some(existing_str) = existing.as_str() else {
            continue;
        };
        let new_spec = preserve_constraint_prefix(existing_str, new_version);
        *existing = serde_json::Value::String(new_spec);
        edited = true;
        break;
    }
    if !edited {
        return Ok(false);
    }
    let pretty = serde_json::to_string_pretty(&value)
        .map_err(|e| Error::other(format!("{} re-serialize: {e}", path.display())))?;
    let mut bytes = pretty.into_bytes();
    // npm/pnpm append a trailing newline; mirror that convention.
    if !bytes.ends_with(b"\n") {
        bytes.push(b'\n');
    }
    std::fs::write(path, bytes).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(true)
}

/// Resolve the install version string to pass to npm/pnpm/yarn for a
/// LockfileOnly bump. Aliased entries (`npm:<target>@...`) require the
/// alias prefix to be re-emitted on the install spec so npm targets the
/// real registry package — passing a bare version would make npm look
/// for a registry package literally named after the local alias key.
///
/// Returns `new_version` verbatim for non-aliased entries (the common
/// case) and for entries the resolver can't classify.
fn resolve_install_version(tree_path: &Path, name: &str, new_version: &str) -> Result<String> {
    let pkg_path = tree_path.join("package.json");
    let text = std::fs::read_to_string(&pkg_path).map_err(|source| Error::Io {
        path: pkg_path.clone(),
        source,
    })?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| Error::other(format!("{}: {e}", pkg_path.display())))?;
    for field in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        let Some(existing) = value
            .get(field)
            .and_then(|v| v.as_object())
            .and_then(|obj| obj.get(name))
            .and_then(|v| v.as_str())
        else {
            continue;
        };
        if let Some((target, _)) = split_alias_spec(existing) {
            return Ok(format!("npm:{target}@{new_version}"));
        }
        return Ok(new_version.to_string());
    }
    Ok(new_version.to_string())
}

/// Parse an `npm:<target-pkg>@<version-spec>` alias specifier into its
/// two parts. Returns `None` for non-alias specs.
///
/// The target package may be scoped (`@scope/pkg`); its leading `@` is
/// at index 0 of `rest` and is NOT the version separator. The version
/// separator is the rightmost `@` at index > 0.
fn split_alias_spec(spec: &str) -> Option<(&str, &str)> {
    let rest = spec.strip_prefix("npm:")?;
    let idx = rest
        .char_indices()
        .filter(|(i, c)| *c == '@' && *i > 0)
        .map(|(i, _)| i)
        .next_back()?;
    Some((&rest[..idx], &rest[idx + 1..]))
}

fn preserve_constraint_prefix(existing: &str, new_version: &str) -> String {
    // npm alias: `"<local-key>": "npm:<target-pkg>@<version-spec>"`. The
    // inner version-spec follows the same prefix conventions as a normal
    // npm dep; recurse to apply them, then reassemble with the alias
    // target intact. Without this, the catch-all "replace verbatim"
    // branch at the bottom would wipe the `npm:<target>@` prefix and
    // silently break package resolution (npm would then try to fetch a
    // registry package literally named after the local key).
    if let Some((target, inner)) = split_alias_spec(existing) {
        let new_inner = preserve_constraint_prefix(inner, new_version);
        return format!("npm:{target}@{new_inner}");
    }
    if let Some(rest) = existing.strip_prefix('^')
        && rest.contains(|c: char| c.is_ascii_digit())
    {
        return format!("^{new_version}");
    }
    if let Some(rest) = existing.strip_prefix('~')
        && rest.contains(|c: char| c.is_ascii_digit())
    {
        return format!("~{new_version}");
    }
    if existing.starts_with('=') {
        return format!("={new_version}");
    }
    // Bare version (`"1.0.0"`) — apply npm's default caret on update.
    if existing.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return format!("^{new_version}");
    }
    // Anything else (range expressions, tags, file:, git:) is opaque to
    // us; replace verbatim and trust the user to inspect the diff.
    new_version.to_string()
}

/// Platform-aware binary name for npm/pnpm. On Windows, the actual
/// executables are `.cmd` shims around node scripts; `Command::new`
/// uses `CreateProcess` which only auto-resolves `.exe`, so we must
/// say `.cmd` explicitly. On Unix the bare name works.
fn npm_binary_name(flavor: NpmFlavor) -> &'static str {
    match (flavor, cfg!(windows)) {
        (NpmFlavor::Npm, true) => "npm.cmd",
        (NpmFlavor::Npm, false) => "npm",
        (NpmFlavor::Pnpm, true) => "pnpm.cmd",
        (NpmFlavor::Pnpm, false) => "pnpm",
        // yarn1 and yarn berry share the `yarn` shim — berry projects
        // route through corepack or `.yarn/releases/yarn-*.cjs`, but
        // from assay's point of view the binary on PATH is the same
        // name and the per-project resolution picks the right binary.
        (NpmFlavor::Yarn | NpmFlavor::YarnBerry, true) => "yarn.cmd",
        (NpmFlavor::Yarn | NpmFlavor::YarnBerry, false) => "yarn",
    }
}

/// Reverse [`npm_binary_name`]; used by the install path to recover the
/// flavor when it has only the bin string in hand. Returns `Yarn`
/// (yarn1) for the yarn shim because the bin name alone can't
/// distinguish yarn1 from berry — the diagnostic uses this for the
/// error message wording, which is the same for both ("yarn not found").
fn flavor_from_binary_name(bin: &str) -> Option<NpmFlavor> {
    match bin {
        "npm" | "npm.cmd" => Some(NpmFlavor::Npm),
        "pnpm" | "pnpm.cmd" => Some(NpmFlavor::Pnpm),
        "yarn" | "yarn.cmd" => Some(NpmFlavor::Yarn),
        _ => None,
    }
}

/// Convert a spawn-time `io::Error` into a flavor-aware [`Error`].
/// When the kind is `NotFound` (the package manager isn't on PATH),
/// the message names the flavor — far more useful than the generic
/// `io error reading {repo}: program not found` that bubbled up before
/// (see dogfood-tour-2026-05-19 finding E). All other IO failures
/// pass through verbatim.
fn map_npm_spawn_io(source: std::io::Error, bin: &str, flavor: NpmFlavor, repo: &Path) -> Error {
    if source.kind() == std::io::ErrorKind::NotFound {
        let flavor_name = match flavor {
            NpmFlavor::Npm => "npm",
            NpmFlavor::Pnpm => "pnpm",
            NpmFlavor::Yarn | NpmFlavor::YarnBerry => "yarn",
        };
        return Error::other(format!(
            "{bin} not found on PATH; install {flavor_name} to analyze \
             {flavor_name}-flavored projects (detected from lockfile at `{}`)",
            repo.display()
        ));
    }
    Error::Io {
        path: repo.to_path_buf(),
        source,
    }
}

fn sanitize_id_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut last_was_dash = false;
    for ch in value.chars().flat_map(|c| c.to_lowercase()) {
        let safe = if ch.is_ascii_alphanumeric() { ch } else { '-' };
        if safe == '-' {
            if !last_was_dash {
                out.push(safe);
            }
            last_was_dash = true;
        } else {
            out.push(safe);
            last_was_dash = false;
        }
    }
    out.trim_matches('-').to_string()
}

/// Set the `cohort` field on every proposal whose subject matches a
/// known framework cohort definition. Pure annotation pass — no
/// proposals are added, dropped, or rewritten; just tagged so the
/// reporter can group them under one heading and the validator/
/// applier can treat them as atomic units. Stand-alone packages
/// (`lodash`, `typescript`, `vite`, `@types/*`, etc.) keep
/// `cohort: None`. See [`npm_cohorts::KNOWN_COHORTS`].
pub(crate) fn tag_proposals_with_cohorts(proposals: &mut [Proposal]) {
    for p in proposals.iter_mut() {
        if let Some(c) = super::npm_cohorts::match_cohort(&p.subject) {
            p.cohort = Some(c.id.to_string());
        }
    }
}

/// Multi-cohort lockstep tier widening. When two or more proposals
/// share a cohort id, the lockstep nature of framework upgrades
/// (e.g. `@angular/core` + `@angular/common` must move together)
/// means the *effective* tier of every member is the most invasive
/// tier among them. A `@angular/core` Breaking bump bundled with a
/// `@angular/common` Compatible bump can NOT be applied as
/// "Compatible for common, Breaking for core" — pnpm/npm will
/// refuse to resolve the lockfile that way, and even if it did, the
/// runtime contract demands both at the same major.
///
/// This function raises each lockstep member's `bump_tier` to the
/// cohort's max tier (Breaking > Compatible > LockfileOnly) so that
/// downstream gating, reporting, and apply decisions treat the
/// whole group consistently. Members that were already at the max
/// tier are untouched. Widened members get a structured note
/// (`cohort-lockstep: widened from <orig> to <max> to match
/// <cohort>`) so the operator can see at a glance why a normally
/// Compatible bump is being flagged as Breaking.
///
/// Single-member cohorts (a `@angular/core` proposal with no
/// `@angular/common` peer in the same run) are NOT widened — there
/// is no lockstep to enforce when only one member of the group is
/// in scope. The function is a no-op on proposal sets without
/// cohorts.
///
/// Order of operations matters: this MUST run AFTER
/// [`tag_proposals_with_cohorts`] (so `cohort` is populated) and
/// BEFORE [`annotate_proposals_with_overrides`] (so the override
/// note appears alongside any widening note rather than being
/// shoved off by a later mutation pass).
pub(crate) fn widen_cohort_tiers(proposals: &mut [Proposal]) {
    use std::collections::BTreeMap;

    let mut max_tier_by_cohort: BTreeMap<String, BumpTier> = BTreeMap::new();
    let mut cohort_member_count: BTreeMap<String, usize> = BTreeMap::new();
    for p in proposals.iter() {
        let Some(cohort) = p.cohort.as_deref() else {
            continue;
        };
        *cohort_member_count.entry(cohort.to_string()).or_insert(0) += 1;
        let entry = max_tier_by_cohort
            .entry(cohort.to_string())
            .or_insert(BumpTier::LockfileOnly);
        if tier_severity(p.bump_tier) > tier_severity(*entry) {
            *entry = p.bump_tier;
        }
    }
    for p in proposals.iter_mut() {
        let Some(cohort) = p.cohort.as_deref() else {
            continue;
        };
        let count = cohort_member_count.get(cohort).copied().unwrap_or(0);
        if count < 2 {
            continue;
        }
        let max = max_tier_by_cohort
            .get(cohort)
            .copied()
            .unwrap_or(BumpTier::LockfileOnly);
        if tier_severity(max) > tier_severity(p.bump_tier) {
            let orig = p.bump_tier;
            p.bump_tier = max;
            p.notes.push(format!(
                "cohort-lockstep: widened from {} to {} to match {} (lockstep with {} member{})",
                orig.as_str(),
                max.as_str(),
                cohort,
                count,
                if count == 1 { "" } else { "s" }
            ));
        }
    }
}

/// Severity ranking for [`BumpTier`] — higher = more invasive.
/// Used by cohort lockstep widening to pick the dominant tier
/// across cohort members. Kept as a local helper rather than
/// `impl Ord` on `BumpTier` so the public enum stays free of
/// implicit ordering semantics (a future tier reorder would
/// otherwise silently change behavior).
fn tier_severity(t: BumpTier) -> u8 {
    match t {
        BumpTier::LockfileOnly => 0,
        BumpTier::Compatible => 1,
        BumpTier::Breaking => 2,
    }
}

/// Read the project's override declarations (npm `overrides`,
/// pnpm.overrides, yarn `resolutions`) from `package.json` and
/// attach a `note: "override-pinned to <version>"` to every proposal
/// whose subject is governed by an override. The proposal is NOT
/// dropped — the user still wants to see what the registry has —
/// but the note flags that adopting the proposal would conflict
/// with the existing pin. Slate dogfood: 4 packages in `overrides`
/// (chevrotain, langium, dompurify, lodash-es) were silently
/// ignored; the operator had no signal that bumping any of them
/// would fight the override.
///
/// Best-effort: a missing or malformed `package.json` produces no
/// annotations. Nested override paths (e.g. `"foo > bar"` meaning
/// "only when foo depends on bar") are flattened conservatively —
/// the bare package name on the LHS is treated as the override key
/// because that's what assay's exact-match against `Proposal.subject`
/// can act on.
pub(crate) fn annotate_proposals_with_overrides(proposals: &mut [Proposal], repo: &Path) {
    let overrides = match read_package_overrides(repo) {
        Some(m) if !m.is_empty() => m,
        _ => return,
    };
    for p in proposals.iter_mut() {
        if let Some(pin) = overrides.get(&p.subject) {
            p.notes.push(format!(
                "override-pinned to {pin}; adopting this bump would conflict"
            ));
        }
    }
}

/// Parse `package.json` for npm `overrides`, pnpm `pnpm.overrides`,
/// and yarn `resolutions` blocks. Returns a flat map from package
/// name → pinned spec. Returns `None` when the file is absent or
/// can't be parsed (the propose flow is best-effort; an unreadable
/// manifest just means no annotations).
fn read_package_overrides(repo: &Path) -> Option<BTreeMap<String, String>> {
    let path = repo.join("package.json");
    let text = std::fs::read_to_string(&path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    if let Some(obj) = json.get("overrides").and_then(|v| v.as_object()) {
        flatten_overrides(obj, &mut out);
    }
    if let Some(obj) = json
        .get("pnpm")
        .and_then(|p| p.get("overrides"))
        .and_then(|v| v.as_object())
    {
        flatten_overrides(obj, &mut out);
    }
    if let Some(obj) = json.get("resolutions").and_then(|v| v.as_object()) {
        flatten_overrides(obj, &mut out);
    }
    Some(out)
}

/// Flatten an npm/pnpm/yarn override block into `name -> spec`.
///
/// Three shapes are recognized:
///
/// - `"lodash": "1.0.0"` → `lodash` pinned to `1.0.0`.
/// - `"lodash": { "..": "1.0.0" }` → pnpm conditional override; the
///   `..` key means "regardless of parent" so this also pins
///   `lodash` to `1.0.0`. Other parent-keyed forms (e.g.
///   `"react": "18.0.0"` nested under `lodash`) are recorded with
///   the nested package name (`react`) as the pin target — that's
///   the npm semantic of "when X is a transitive of Y, force Y to
///   version Z."
/// - `"foo > bar": "1.0.0"` → npm path-key override; the
///   right-most segment (`bar`) is the package being pinned.
fn flatten_overrides(
    obj: &serde_json::Map<String, serde_json::Value>,
    out: &mut BTreeMap<String, String>,
) {
    for (key, value) in obj {
        let pkg_name = override_key_to_package_name(key);
        match value {
            serde_json::Value::String(s) => {
                out.insert(pkg_name.to_string(), s.clone());
            }
            serde_json::Value::Object(nested) => {
                if let Some(serde_json::Value::String(s)) = nested.get("..") {
                    out.insert(pkg_name.to_string(), s.clone());
                }
                // Nested non-".." entries describe parent-scoped
                // pins; the inner key is the package being pinned.
                for (inner_key, inner_value) in nested {
                    if inner_key == ".." {
                        continue;
                    }
                    if let serde_json::Value::String(s) = inner_value {
                        let inner_pkg = override_key_to_package_name(inner_key);
                        out.insert(inner_pkg.to_string(), s.clone());
                    }
                }
            }
            _ => {}
        }
    }
}

/// Resolve an npm/pnpm/yarn override-key into a bare package name.
/// Keys like `"lodash"` → `lodash`; `"foo > bar"` (npm path form)
/// → `bar` (the right-most segment is the pinned package); empty or
/// malformed keys fall through to the original string so the caller
/// sees them in the receipt for debugging.
fn override_key_to_package_name(key: &str) -> &str {
    if let Some((_, tail)) = key.rsplit_once('>') {
        return tail.trim();
    }
    key.trim()
}

/// Drop proposals whose `subject` exactly matches an entry in the
/// per-ecosystem ignore list. Mirrors `filter_ignored_crates`
/// ([`crate::ecosystem::cargo`]) and `filter_ignored_actions`
/// ([`crate::ecosystem::github_actions`]) so `--ignore npm:<name>`
/// behaves the same way across ecosystems. Scoped subjects like
/// `@angular/core` work because the comparison is byte-for-byte.
pub(crate) fn filter_ignored_packages(
    proposals: Vec<Proposal>,
    ignored: &[String],
) -> Vec<Proposal> {
    if ignored.is_empty() {
        return proposals;
    }
    proposals
        .into_iter()
        .filter(|p| !ignored.iter().any(|i| i == &p.subject))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // parse_npm_outdated_output
    // -------------------------------------------------------------------------

    #[test]
    fn parse_outdated_handles_typical_npm_json() {
        let stdout = r#"{
            "lodash": {
                "current": "4.17.20",
                "wanted":  "4.17.21",
                "latest":  "4.17.21",
                "dependent": "my-app"
            },
            "react": {
                "current": "17.0.0",
                "wanted":  "17.0.2",
                "latest":  "18.3.1",
                "dependent": "my-app"
            }
        }"#;
        let rows = parse_npm_outdated_output(stdout).unwrap();
        assert_eq!(rows.len(), 2);
        // Sorted by name → lodash, react.
        assert_eq!(rows[0].name, "lodash");
        assert_eq!(rows[0].current.as_deref(), Some("4.17.20"));
        assert_eq!(rows[0].wanted, "4.17.21");
        assert_eq!(rows[0].latest, "4.17.21");
        assert_eq!(rows[1].name, "react");
        assert_eq!(rows[1].current.as_deref(), Some("17.0.0"));
    }

    #[test]
    fn parse_outdated_handles_empty_object() {
        let rows = parse_npm_outdated_output("{}").unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn parse_outdated_handles_empty_string() {
        let rows = parse_npm_outdated_output("").unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn parse_outdated_handles_missing_current() {
        // Package declared but not installed — `current` is absent.
        let stdout = r#"{"chalk":{"wanted":"4.1.2","latest":"5.3.0"}}"#;
        let rows = parse_npm_outdated_output(stdout).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].current, None);
    }

    #[test]
    fn yarn_lock_is_berry_detects_metadata_header() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        // yarn berry shape — has `__metadata:` block at top.
        std::fs::write(
            repo.join("yarn.lock"),
            "# This file is generated by running \"yarn install\" inside your project.\n\
             # Manual changes might be lost - proceed with caution!\n\
             \n\
             __metadata:\n  version: 9\n  cacheKey: 10\n\n\
             \"@angular/compiler@npm:21.2.13\":\n  version: 21.2.13\n",
        )
        .unwrap();
        assert!(yarn_lock_is_berry(repo));
    }

    #[test]
    fn yarn_lock_is_berry_returns_false_for_yarn1() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        // yarn1 shape — no `__metadata:` block.
        std::fs::write(
            repo.join("yarn.lock"),
            "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n\
             # yarn lockfile v1\n\n\
             ansi-styles@^4.1.0:\n  version \"4.3.0\"\n",
        )
        .unwrap();
        assert!(!yarn_lock_is_berry(repo));
    }

    #[test]
    fn yarn_lock_is_berry_returns_false_when_file_absent() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!yarn_lock_is_berry(tmp.path()));
    }

    // -------------------------------------------------------------------------
    // yarn berry proposer — descriptor + lockfile parser + flavor routing.
    // -------------------------------------------------------------------------

    #[test]
    fn detect_flavor_returns_yarn_berry_when_metadata_present() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        std::fs::write(repo.join("package.json"), "{}").unwrap();
        std::fs::write(
            repo.join("yarn.lock"),
            "__metadata:\n  version: 9\n\n\"x@npm:^1\":\n  version: 1.0.0\n",
        )
        .unwrap();
        assert_eq!(detect_flavor(repo), Some(NpmFlavor::YarnBerry));
    }

    #[test]
    fn detect_flavor_returns_yarn1_when_no_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        std::fs::write(repo.join("package.json"), "{}").unwrap();
        std::fs::write(
            repo.join("yarn.lock"),
            "# yarn lockfile v1\n\nx@^1.0.0:\n  version \"1.0.0\"\n",
        )
        .unwrap();
        assert_eq!(detect_flavor(repo), Some(NpmFlavor::Yarn));
    }

    #[test]
    fn parse_berry_descriptor_name_handles_unscoped_packages() {
        assert_eq!(
            parse_berry_descriptor_name("lodash@npm:^4.17.21"),
            Some("lodash".into())
        );
        assert_eq!(
            parse_berry_descriptor_name("\"lodash@npm:^4.17.21\""),
            Some("lodash".into())
        );
    }

    #[test]
    fn parse_berry_descriptor_name_handles_scoped_packages() {
        assert_eq!(
            parse_berry_descriptor_name("@types/node@npm:^20.10.0"),
            Some("@types/node".into())
        );
        assert_eq!(
            parse_berry_descriptor_name("\"@angular/compiler@npm:21.2.13\""),
            Some("@angular/compiler".into())
        );
    }

    #[test]
    fn parse_berry_descriptor_name_handles_workspace_protocol() {
        assert_eq!(
            parse_berry_descriptor_name("my-pkg@workspace:^"),
            Some("my-pkg".into())
        );
    }

    #[test]
    fn parse_berry_lockfile_extracts_subject_to_version_map() {
        let lockfile = "__metadata:\n  version: 9\n  cacheKey: 10\n\n\
                        \"lodash@npm:^4.17.21\":\n  version: 4.17.21\n  resolution: \"lodash@npm:4.17.21\"\n\n\
                        \"@types/node@npm:^20.10.0\":\n  version: 20.10.5\n  resolution: \"@types/node@npm:20.10.5\"\n";
        let map = parse_berry_lockfile(lockfile).unwrap();
        assert_eq!(map.get("lodash").map(String::as_str), Some("4.17.21"));
        assert_eq!(map.get("@types/node").map(String::as_str), Some("20.10.5"));
    }

    #[test]
    fn parse_berry_lockfile_skips_metadata_block() {
        let lockfile = "__metadata:\n  version: 9\n\n\"x@npm:^1\":\n  version: 1.0.0\n";
        let map = parse_berry_lockfile(lockfile).unwrap();
        assert!(!map.contains_key("__metadata"));
        assert_eq!(map.get("x").map(String::as_str), Some("1.0.0"));
    }

    #[test]
    fn parse_berry_lockfile_handles_comma_separated_descriptors() {
        // Multiple descriptors for the same resolution share an entry.
        // Both should yield the same version.
        let lockfile = "\"lodash@npm:^4.17.21, lodash@npm:^4.17.20\":\n  version: 4.17.21\n";
        let map = parse_berry_lockfile(lockfile).unwrap();
        assert_eq!(map.get("lodash").map(String::as_str), Some("4.17.21"));
    }

    #[test]
    fn parse_berry_lockfile_skips_entries_without_version() {
        // Workspace-protocol entries often have a `linkType:` and a
        // `version` field, but defensive: if `version` is missing, skip.
        let lockfile = "\"odd-one@workspace:packages/odd\":\n  resolution: \"odd-one@workspace:packages/odd\"\n";
        let map = parse_berry_lockfile(lockfile).unwrap();
        assert!(!map.contains_key("odd-one"));
    }

    #[test]
    fn parse_berry_lockfile_returns_empty_for_garbage() {
        // Malformed YAML returns an error, but the parser surfaces it
        // via Result rather than panicking. The proposer routes
        // through Err and aborts the scan_root.
        let map = parse_berry_lockfile("__metadata:\n  version: 9\n");
        assert!(map.is_ok());
    }

    #[test]
    fn propose_berry_updates_returns_empty_when_no_direct_deps() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        std::fs::write(repo.join("package.json"), "{}").unwrap();
        std::fs::write(repo.join("yarn.lock"), "__metadata:\n  version: 9\n").unwrap();
        let proposals = propose_berry_updates(repo, &[]).unwrap();
        assert!(proposals.is_empty());
    }

    #[test]
    fn collect_direct_deps_with_constraints_records_constraint_strings() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        std::fs::write(
            repo.join("package.json"),
            r#"{"dependencies":{"lodash":"^4.17.21"},"devDependencies":{"@types/node":"~20.10.0"}}"#,
        )
        .unwrap();
        let deps = collect_direct_deps_with_constraints(repo).unwrap();
        assert_eq!(deps.get("lodash").map(String::as_str), Some("^4.17.21"));
        assert_eq!(
            deps.get("@types/node").map(String::as_str),
            Some("~20.10.0")
        );
    }

    #[test]
    fn parse_outdated_skips_file_link_workspace_deps() {
        // pnpm outdated -r emits entries for `file:` / `workspace:` deps
        // with no `latest` (and/or a path-shaped `wanted`). These can't
        // be bumped against a registry, so the parser drops them.
        // Captured shape: real `pnpm outdated -r` against vite's
        // `@vitejs/test-aliased-module` entry.
        let stdout = r#"{
            "regular": {"current":"1.0.0","wanted":"1.0.1","latest":"1.0.1"},
            "@vitejs/test-aliased-module": {
                "wanted": "@vitejs/test-aliased-module@file:playground/alias/dir/module",
                "isDeprecated": false,
                "dependencyType": "dependencies"
            },
            "internal-pkg": {
                "wanted": "workspace:^",
                "isDeprecated": false
            }
        }"#;
        let rows = parse_npm_outdated_output(stdout).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "regular");
    }

    #[test]
    fn parse_outdated_collapses_workspace_per_consumer_arrays() {
        // npm 7+ workspaces emit ONE array per dep, with one entry per
        // consumer. The (current, wanted, latest) tuple is identical
        // across entries because npm hoists deps. Parser must accept
        // the array shape and emit exactly one row per dep.
        let stdout = r#"{
            "lodash": [
                {"current":"4.17.20","wanted":"4.17.20","latest":"4.18.1","dependent":"alpha"},
                {"current":"4.17.20","wanted":"4.17.20","latest":"4.18.1","dependent":"beta"}
            ],
            "chalk": [
                {"current":"4.1.0","wanted":"4.1.0","latest":"5.3.0","dependent":"alpha"}
            ]
        }"#;
        let rows = parse_npm_outdated_output(stdout).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "chalk");
        assert_eq!(rows[0].current.as_deref(), Some("4.1.0"));
        assert_eq!(rows[0].latest, "5.3.0");
        assert_eq!(rows[1].name, "lodash");
        assert_eq!(rows[1].current.as_deref(), Some("4.17.20"));
        assert_eq!(rows[1].latest, "4.18.1");
    }

    // -------------------------------------------------------------------------
    // yarn1 NDJSON parser
    // -------------------------------------------------------------------------

    #[test]
    fn parse_yarn1_outdated_extracts_table_rows() {
        // Real-ish shape from `yarn outdated --json` (yarn 1.22).
        let stdout = r#"{"type":"info","data":"Color legend : ..."}
{"type":"table","data":{"head":["Package","Current","Wanted","Latest","Package Type","URL"],"body":[["lodash","4.17.20","4.17.21","4.18.1","dependencies","https://lodash.com/"],["axios","1.6.0","1.6.7","1.16.1","dependencies","https://axios-http.com/"]]}}"#;
        let rows = parse_yarn1_outdated_output(stdout).unwrap();
        assert_eq!(rows.len(), 2);
        // Sorted by name → axios first.
        assert_eq!(rows[0].name, "axios");
        assert_eq!(rows[0].current.as_deref(), Some("1.6.0"));
        assert_eq!(rows[0].wanted, "1.6.7");
        assert_eq!(rows[0].latest, "1.16.1");
        assert_eq!(rows[1].name, "lodash");
    }

    #[test]
    fn parse_yarn1_outdated_returns_empty_when_no_table_line() {
        // yarn emits an info preamble even when nothing is outdated.
        let stdout = r#"{"type":"info","data":"Use \"yarn outdated --help\" for more"}"#;
        let rows = parse_yarn1_outdated_output(stdout).unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn parse_yarn1_outdated_handles_empty_string() {
        assert!(parse_yarn1_outdated_output("").unwrap().is_empty());
    }

    #[test]
    fn parse_yarn1_outdated_ignores_garbage_lines() {
        // Mixed valid + invalid lines — invalid skipped, valid kept.
        let stdout = "not json\n{\"type\":\"table\",\"data\":{\"head\":[],\"body\":[[\"a\",\"1.0\",\"1.0\",\"2.0\",\"dependencies\",\"\"]]}}\n";
        let rows = parse_yarn1_outdated_output(stdout).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "a");
    }

    // -------------------------------------------------------------------------
    // build_npm_proposals
    // -------------------------------------------------------------------------

    #[test]
    fn build_proposals_tier_maps_correctly() {
        let rows = vec![
            NpmOutdatedRow {
                name: "lodash".into(),
                current: Some("4.17.20".into()),
                wanted: "4.17.21".into(),
                latest: "4.17.21".into(),
            },
            NpmOutdatedRow {
                name: "react".into(),
                current: Some("17.0.0".into()),
                wanted: "17.0.2".into(),
                latest: "18.3.1".into(),
            },
            NpmOutdatedRow {
                name: "chalk".into(),
                current: Some("4.1.2".into()),
                wanted: "4.1.2".into(),
                latest: "5.3.0".into(),
            },
        ];
        let proposals = build_npm_proposals(&rows, &[PathBuf::from("package.json")]);
        assert_eq!(proposals.len(), 3);
        let by_name: BTreeMap<&str, &Proposal> =
            proposals.iter().map(|p| (p.subject.as_str(), p)).collect();
        // lodash: wanted == latest → LockfileOnly.
        assert_eq!(by_name["lodash"].bump_tier, BumpTier::LockfileOnly);
        // react: wanted (17.0.2) != latest (18.3.1), cross-major → Breaking.
        assert_eq!(by_name["react"].bump_tier, BumpTier::Breaking);
        // chalk: wanted (4.1.2) != latest (5.3.0), cross-major → Breaking.
        assert_eq!(by_name["chalk"].bump_tier, BumpTier::Breaking);
    }

    #[test]
    fn build_proposals_skips_rows_where_current_equals_latest() {
        // npm outdated without node_modules sometimes lists packages
        // whose lockfile already matches latest. The proposer must
        // drop those so the report doesn't show "5.2.9 -> 5.2.9".
        let rows = vec![NpmOutdatedRow {
            name: "@fontsource/inter".into(),
            current: Some("5.2.8".into()),
            wanted: "5.2.8".into(),
            latest: "5.2.8".into(),
        }];
        let proposals = build_npm_proposals(&rows, &[]);
        assert!(proposals.is_empty());
    }

    #[test]
    fn build_proposals_skips_rows_without_current_version() {
        let rows = vec![NpmOutdatedRow {
            name: "chalk".into(),
            current: None,
            wanted: "4.1.2".into(),
            latest: "5.3.0".into(),
        }];
        let proposals = build_npm_proposals(&rows, &[]);
        assert!(proposals.is_empty());
    }

    // -------------------------------------------------------------------------
    // classify_npm_bump — same caret-compat-group rules as cargo
    // -------------------------------------------------------------------------

    #[test]
    fn classify_npm_same_major_is_compatible() {
        assert_eq!(classify_npm_bump("1.0.0", "1.5.0"), BumpTier::Compatible);
        assert_eq!(classify_npm_bump("17.0.0", "17.0.2"), BumpTier::Compatible);
    }

    #[test]
    fn classify_npm_cross_major_is_breaking() {
        assert_eq!(classify_npm_bump("17.0.0", "18.0.0"), BumpTier::Breaking);
        assert_eq!(classify_npm_bump("0.8.0", "1.0.0"), BumpTier::Breaking);
    }

    #[test]
    fn classify_npm_zero_dot_x_groups_by_minor() {
        assert_eq!(classify_npm_bump("0.18.1", "0.18.7"), BumpTier::Compatible);
        assert_eq!(classify_npm_bump("0.18.1", "0.20.0"), BumpTier::Breaking);
    }

    // -------------------------------------------------------------------------
    // explain_npm_bump — structured rationale for --explain.
    // -------------------------------------------------------------------------

    #[test]
    fn explain_npm_same_major_1_plus_returns_compatible() {
        let exp = explain_npm_bump("1.0.0", "1.5.0");
        assert_eq!(exp.decision, "compatible");
        assert_eq!(exp.rule, "npm:caret-major-1-plus");
    }

    #[test]
    fn explain_npm_cross_major_returns_breaking() {
        let exp = explain_npm_bump("1.5.0", "2.0.0");
        assert_eq!(exp.decision, "breaking");
        assert_eq!(exp.rule, "npm:caret-major-crossed");
    }

    #[test]
    fn explain_npm_cross_minor_in_0_x_returns_breaking() {
        let exp = explain_npm_bump("0.18.1", "0.20.0");
        assert_eq!(exp.decision, "breaking");
        assert_eq!(exp.rule, "npm:caret-0-x-minor-crossed");
    }

    #[test]
    fn explain_npm_unparseable_returns_breaking() {
        let exp = explain_npm_bump("not-a-version", "1.0.0");
        assert_eq!(exp.decision, "breaking");
        assert_eq!(exp.rule, "npm:unparseable-semver");
    }

    #[test]
    fn explain_npm_lockfile_only_carries_constraint() {
        let exp = explain_npm_lockfile_only_bump("4.17.20", "4.17.21", Some("^4.17.0"));
        assert_eq!(exp.decision, "lockfile-only");
        assert_eq!(exp.rule, "npm:lockfile-within-constraint");
        assert_eq!(
            exp.inputs.get("constraint").map(String::as_str),
            Some("^4.17.0")
        );
    }

    // -------------------------------------------------------------------------
    // preserve_constraint_prefix
    // -------------------------------------------------------------------------

    #[test]
    fn preserve_prefix_keeps_caret() {
        assert_eq!(preserve_constraint_prefix("^1.0.0", "1.5.2"), "^1.5.2");
    }

    #[test]
    fn preserve_prefix_keeps_tilde() {
        assert_eq!(preserve_constraint_prefix("~1.0.0", "1.5.2"), "~1.5.2");
    }

    #[test]
    fn preserve_prefix_keeps_exact_equality() {
        assert_eq!(preserve_constraint_prefix("=1.0.0", "1.5.2"), "=1.5.2");
    }

    #[test]
    fn preserve_prefix_adds_caret_to_bare_version() {
        // npm install --save defaults to caret-prefixed when adding a
        // dep that previously had a bare version. Mirror that here.
        assert_eq!(preserve_constraint_prefix("1.0.0", "1.5.2"), "^1.5.2");
    }

    #[test]
    fn preserve_prefix_opaque_for_unknown_shapes() {
        // file:, git+ssh://, npm tag references, etc. — replace verbatim.
        assert_eq!(
            preserve_constraint_prefix("file:../local", "1.5.2"),
            "1.5.2",
        );
    }

    // -------------------------------------------------------------------------
    // npm alias syntax: `<local-key>: "npm:<target-pkg>@<version-spec>"`.
    // npm's `outdated --json` keys by the LOCAL alias name, so the proposer
    // emits proposal.subject = local key (e.g. "my-lodash"). The editor
    // finds the entry correctly, but `preserve_constraint_prefix` pre-fix
    // fell into the catch-all "replace verbatim" branch and wiped the
    // entire `npm:lodash@` alias prefix — turning
    //   "my-lodash": "npm:lodash@4.17.21"
    // into
    //   "my-lodash": "4.17.22"
    // which breaks package resolution (npm would now try to fetch a
    // registry package literally named `my-lodash`).
    //
    // Surfaces post-cargo-renamed-dep dogfood (2026-05-18): same class of
    // aliased-dep bug as cargo's `package = "..."` syntax, different shape
    // (cargo missed the lookup; npm finds it but corrupts the value).
    // -------------------------------------------------------------------------

    #[test]
    fn preserve_prefix_handles_npm_alias_bare_inner_version() {
        // Bare inner version follows npm's --save convention: gain a caret
        // on update. Same rule the top-level bare-version path applies.
        assert_eq!(
            preserve_constraint_prefix("npm:lodash@4.17.21", "4.17.22"),
            "npm:lodash@^4.17.22",
        );
    }

    #[test]
    fn preserve_prefix_handles_npm_alias_caret_inner() {
        assert_eq!(
            preserve_constraint_prefix("npm:lodash@^4.17.21", "4.17.22"),
            "npm:lodash@^4.17.22",
        );
    }

    #[test]
    fn preserve_prefix_handles_npm_alias_tilde_inner() {
        assert_eq!(
            preserve_constraint_prefix("npm:lodash@~4.17.21", "4.17.22"),
            "npm:lodash@~4.17.22",
        );
    }

    #[test]
    fn preserve_prefix_handles_npm_alias_with_scoped_target() {
        // `@scope/pkg` introduces a leading `@` that is NOT the version
        // separator; the version `@` is the LAST one.
        assert_eq!(
            preserve_constraint_prefix("npm:@types/lodash@^4.17.21", "4.17.22"),
            "npm:@types/lodash@^4.17.22",
        );
    }

    // -------------------------------------------------------------------------
    // try_edit_package_json
    // -------------------------------------------------------------------------

    #[test]
    fn editor_widens_dependencies_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg = tmp.path().join("package.json");
        std::fs::write(
            &pkg,
            r#"{
  "name": "sample",
  "version": "0.1.0",
  "dependencies": {
    "lodash": "^4.17.20"
  }
}
"#,
        )
        .unwrap();
        let edited = try_edit_package_json(&pkg, "lodash", "4.17.21").unwrap();
        assert!(edited);
        let after = std::fs::read_to_string(&pkg).unwrap();
        assert!(after.contains(r#""lodash": "^4.17.21""#), "got:\n{after}");
        // Trailing newline preserved (npm convention).
        assert!(after.ends_with('\n'));
    }

    #[test]
    fn editor_widens_dev_dependencies_when_main_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg = tmp.path().join("package.json");
        std::fs::write(
            &pkg,
            r#"{"name":"sample","devDependencies":{"jest":"^28.0.0"}}"#,
        )
        .unwrap();
        let edited = try_edit_package_json(&pkg, "jest", "29.7.0").unwrap();
        assert!(edited);
        let after = std::fs::read_to_string(&pkg).unwrap();
        assert!(after.contains(r#""jest": "^29.7.0""#));
    }

    #[test]
    fn editor_returns_false_when_dep_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg = tmp.path().join("package.json");
        std::fs::write(
            &pkg,
            r#"{"name":"sample","dependencies":{"lodash":"^4.0.0"}}"#,
        )
        .unwrap();
        let edited = try_edit_package_json(&pkg, "missing-pkg", "1.0.0").unwrap();
        assert!(!edited);
    }

    // -------------------------------------------------------------------------
    // resolve_install_version — alias-aware LockfileOnly install spec.
    //
    // Same npm-alias root cause as the editor bug, different code path.
    // `run_install_pinned` builds `<name>@<version>` and shells out to
    // `npm install`. For a LockfileOnly bump on an aliased dep, passing
    // bare `name="my-lodash" version="4.17.22"` produces
    //   npm install my-lodash@4.17.22
    // which fails because `my-lodash` isn't a registry package — it's a
    // local alias for `lodash`. The resolver re-emits the alias so the
    // install spec becomes `my-lodash@npm:lodash@4.17.22`.
    // -------------------------------------------------------------------------

    #[test]
    fn resolve_install_passes_through_bare_version_for_unaliased_dep() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{"name":"sample","dependencies":{"lodash":"^4.17.20"}}"#,
        )
        .unwrap();
        let v = resolve_install_version(tmp.path(), "lodash", "4.17.22").unwrap();
        assert_eq!(v, "4.17.22");
    }

    #[test]
    fn resolve_install_reconstructs_alias_spec_for_aliased_dep() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{"name":"sample","dependencies":{"my-lodash":"npm:lodash@^4.17.21"}}"#,
        )
        .unwrap();
        let v = resolve_install_version(tmp.path(), "my-lodash", "4.17.22").unwrap();
        assert_eq!(v, "npm:lodash@4.17.22");
    }

    #[test]
    fn resolve_install_handles_scoped_alias_target() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{"name":"sample","dependencies":{"local":"npm:@scope/pkg@^1.0.0"}}"#,
        )
        .unwrap();
        let v = resolve_install_version(tmp.path(), "local", "1.0.1").unwrap();
        assert_eq!(v, "npm:@scope/pkg@1.0.1");
    }

    #[test]
    fn resolve_install_finds_alias_under_dev_dependencies() {
        // The resolver scans all four dep-name fields, not just `dependencies`.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{"name":"sample","devDependencies":{"my-jest":"npm:jest@^29.0.0"}}"#,
        )
        .unwrap();
        let v = resolve_install_version(tmp.path(), "my-jest", "29.7.0").unwrap();
        assert_eq!(v, "npm:jest@29.7.0");
    }

    #[test]
    fn editor_preserves_npm_alias_prefix_on_widen() {
        // End-to-end: package.json has an aliased entry; editor must bump
        // the inner version and preserve the `npm:<target>@` prefix
        // verbatim. Pre-fix the value was rewritten to a bare version,
        // silently breaking npm's package resolution.
        let tmp = tempfile::tempdir().unwrap();
        let pkg = tmp.path().join("package.json");
        std::fs::write(
            &pkg,
            r#"{
  "name": "sample",
  "dependencies": {
    "my-lodash": "npm:lodash@^4.17.21"
  }
}
"#,
        )
        .unwrap();
        let edited = try_edit_package_json(&pkg, "my-lodash", "4.17.22").unwrap();
        assert!(edited);
        let after = std::fs::read_to_string(&pkg).unwrap();
        assert!(
            after.contains(r#""my-lodash": "npm:lodash@^4.17.22""#),
            "alias prefix must be preserved, inner version bumped; got:\n{after}",
        );
        // Negative check: a bare-version write would have looked like
        // `"my-lodash": "^4.17.22"`. Make sure that didn't happen.
        assert!(
            !after.contains(r#""my-lodash": "^4.17.22""#),
            "alias prefix was wiped — bug regression; got:\n{after}",
        );
    }

    // -------------------------------------------------------------------------
    // detect_flavor + detect_manifests
    // -------------------------------------------------------------------------

    #[test]
    fn detect_flavor_recognizes_each_lockfile() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        assert!(detect_flavor(root).is_none());
        std::fs::write(root.join("package-lock.json"), "{}").unwrap();
        assert_eq!(detect_flavor(root), Some(NpmFlavor::Npm));
        std::fs::remove_file(root.join("package-lock.json")).unwrap();
        std::fs::write(root.join("pnpm-lock.yaml"), "lockfileVersion: 6.0\n").unwrap();
        assert_eq!(detect_flavor(root), Some(NpmFlavor::Pnpm));
        std::fs::remove_file(root.join("pnpm-lock.yaml")).unwrap();
        std::fs::write(root.join("yarn.lock"), "# yarn lockfile v1\n").unwrap();
        assert_eq!(detect_flavor(root), Some(NpmFlavor::Yarn));
    }

    #[test]
    fn detect_manifests_finds_package_json_and_lockfile() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("package.json"), r#"{"name":"x"}"#).unwrap();
        std::fs::write(root.join("package-lock.json"), "{}").unwrap();
        let eco = NpmEcosystem;
        let manifests = eco.detect_manifests(root).unwrap();
        assert_eq!(manifests.len(), 2);
        assert!(
            manifests
                .iter()
                .any(|m| matches!(m.kind, ManifestKind::PackageJson))
        );
        assert!(
            manifests
                .iter()
                .any(|m| matches!(m.kind, ManifestKind::NpmLockfile))
        );
    }

    // -------------------------------------------------------------------------
    // collect_direct_dep_names + filter
    // -------------------------------------------------------------------------

    #[test]
    fn read_lockfile_versions_parses_v3_packages_map() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": { "name": "root", "version": "0.1.0" },
                    "node_modules/lodash": { "version": "4.17.20" },
                    "node_modules/react": { "version": "17.0.0" },
                    "node_modules/foo/node_modules/lodash": { "version": "3.0.0" }
                }
            }"#,
        )
        .unwrap();
        let map = read_lockfile_versions(tmp.path()).unwrap();
        assert_eq!(map.get("lodash"), Some(&"4.17.20".to_string()));
        assert_eq!(map.get("react"), Some(&"17.0.0".to_string()));
        // Nested duplicate must be ignored — top-level only.
        assert_ne!(map.get("lodash"), Some(&"3.0.0".to_string()));
    }

    #[test]
    fn read_lockfile_versions_returns_empty_when_lockfile_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let map = read_lockfile_versions(tmp.path()).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn collect_direct_dep_names_reads_root_package_json() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{
                "dependencies": { "lodash": "^4.0.0" },
                "devDependencies": { "jest": "^28.0.0" }
            }"#,
        )
        .unwrap();
        let names = collect_direct_dep_names(tmp.path()).unwrap();
        let names: Vec<&String> = names.iter().collect();
        assert_eq!(names, vec![&"jest".to_string(), &"lodash".to_string()]);
    }

    #[test]
    fn filter_to_direct_deps_drops_transitive_entries() {
        let proposals = vec![sample_proposal("lodash"), sample_proposal("@types/node")];
        let direct: BTreeSet<String> = std::iter::once("lodash".to_string()).collect();
        let kept = filter_to_direct_deps(proposals, &direct);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].subject, "lodash");
    }

    #[test]
    fn filter_ignored_packages_drops_matching_subject() {
        let proposals = vec![sample_proposal("typescript"), sample_proposal("lodash")];
        let kept = filter_ignored_packages(proposals, &["typescript".to_string()]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].subject, "lodash");
    }

    #[test]
    fn filter_ignored_packages_handles_scoped_subjects() {
        // `@angular/core` and `@angular/common` differ — only the named
        // one is dropped. Scoped npm packages are subject-matched
        // byte-for-byte (no glob expansion).
        let proposals = vec![
            sample_proposal("@angular/core"),
            sample_proposal("@angular/common"),
        ];
        let kept = filter_ignored_packages(proposals, &["@angular/core".to_string()]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].subject, "@angular/common");
    }

    #[test]
    fn filter_ignored_packages_empty_list_is_identity() {
        let proposals = vec![sample_proposal("lodash"), sample_proposal("typescript")];
        let before = proposals.len();
        let kept = filter_ignored_packages(proposals, &[]);
        assert_eq!(kept.len(), before);
    }

    #[test]
    fn find_peer_dep_consumers_finds_flat_packages_declaring_subject_as_peer() {
        let tmp = tempfile::tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        std::fs::create_dir_all(nm.join("lucide-angular")).unwrap();
        std::fs::write(
            nm.join("lucide-angular").join("package.json"),
            r#"{
                "name": "lucide-angular",
                "version": "0.577.0",
                "peerDependencies": {
                    "@angular/common": "13.x - 21.x",
                    "@angular/core": "13.x - 21.x"
                }
            }"#,
        )
        .unwrap();
        std::fs::create_dir_all(nm.join("lodash")).unwrap();
        std::fs::write(
            nm.join("lodash").join("package.json"),
            r#"{"name": "lodash", "version": "4.17.21"}"#,
        )
        .unwrap();
        let consumers = find_peer_dep_consumers(tmp.path(), "@angular/core");
        assert_eq!(consumers, vec!["lucide-angular"]);
    }

    #[test]
    fn find_peer_dep_consumers_walks_scoped_packages() {
        let tmp = tempfile::tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        std::fs::create_dir_all(nm.join("@wildmason").join("aegis")).unwrap();
        std::fs::write(
            nm.join("@wildmason").join("aegis").join("package.json"),
            r#"{
                "name": "@wildmason/aegis",
                "version": "1.5.4",
                "peerDependencies": { "@angular/cdk": ">=21" }
            }"#,
        )
        .unwrap();
        let consumers = find_peer_dep_consumers(tmp.path(), "@angular/cdk");
        assert_eq!(consumers, vec!["@wildmason/aegis"]);
    }

    #[test]
    fn find_peer_dep_consumers_skips_dot_dirs_and_non_peer_declarations() {
        let tmp = tempfile::tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        // pnpm-style virtual store — skipped because it starts with `.`
        std::fs::create_dir_all(nm.join(".pnpm").join("foo")).unwrap();
        std::fs::write(
            nm.join(".pnpm").join("foo").join("package.json"),
            r#"{"name": "foo", "peerDependencies": {"@angular/core": "^21"}}"#,
        )
        .unwrap();
        // Real package that declares it as `dependencies` (not peer) — skipped
        std::fs::create_dir_all(nm.join("normal-dep")).unwrap();
        std::fs::write(
            nm.join("normal-dep").join("package.json"),
            r#"{"name": "normal-dep", "dependencies": {"@angular/core": "^21"}}"#,
        )
        .unwrap();
        let consumers = find_peer_dep_consumers(tmp.path(), "@angular/core");
        assert!(consumers.is_empty(), "got: {consumers:?}");
    }

    #[test]
    fn find_peer_dep_consumers_handles_missing_node_modules_gracefully() {
        // No node_modules dir → empty result, no crash.
        let tmp = tempfile::tempdir().unwrap();
        let consumers = find_peer_dep_consumers(tmp.path(), "@angular/core");
        assert!(consumers.is_empty());
    }

    #[test]
    fn find_peer_dep_consumers_walks_pnpm_virtual_store() {
        // pnpm layout: node_modules/.pnpm/<pkg>@<ver>/node_modules/<pkg>/package.json
        let tmp = tempfile::tempdir().unwrap();
        let virt = tmp
            .path()
            .join("node_modules")
            .join(".pnpm")
            .join("@wildmason+aegis@1.5.4_@angular+core@21.0.0")
            .join("node_modules")
            .join("@wildmason")
            .join("aegis");
        std::fs::create_dir_all(&virt).unwrap();
        std::fs::write(
            virt.join("package.json"),
            r#"{
                "name": "@wildmason/aegis",
                "version": "1.5.4",
                "peerDependencies": { "@angular/core": ">=21" }
            }"#,
        )
        .unwrap();
        // Also add an unscoped entry to confirm the unscoped path
        // through walk_flat_node_modules works inside the virtual
        // store too.
        let unscoped = tmp
            .path()
            .join("node_modules")
            .join(".pnpm")
            .join("lucide-angular@0.577.0_@angular+core@21.0.0")
            .join("node_modules")
            .join("lucide-angular");
        std::fs::create_dir_all(&unscoped).unwrap();
        std::fs::write(
            unscoped.join("package.json"),
            r#"{
                "name": "lucide-angular",
                "version": "0.577.0",
                "peerDependencies": { "@angular/core": "13.x - 21.x" }
            }"#,
        )
        .unwrap();
        let consumers = find_peer_dep_consumers(tmp.path(), "@angular/core");
        assert_eq!(consumers, vec!["@wildmason/aegis", "lucide-angular"]);
    }

    #[test]
    fn find_peer_dep_consumers_dedupes_across_virtual_store_versions() {
        // Same package at two different peer-resolution suffixes in
        // .pnpm — both declare the subject as a peer. The result
        // should report the package name once, not twice.
        let tmp = tempfile::tempdir().unwrap();
        for suffix in [
            "@wildmason+aegis@1.5.4_@angular+core@21.0.0",
            "@wildmason+aegis@1.5.4_@angular+core@22.0.0",
        ] {
            let pkg = tmp
                .path()
                .join("node_modules")
                .join(".pnpm")
                .join(suffix)
                .join("node_modules")
                .join("@wildmason")
                .join("aegis");
            std::fs::create_dir_all(&pkg).unwrap();
            std::fs::write(
                pkg.join("package.json"),
                r#"{
                    "name": "@wildmason/aegis",
                    "version": "1.5.4",
                    "peerDependencies": { "@angular/core": ">=21" }
                }"#,
            )
            .unwrap();
        }
        let consumers = find_peer_dep_consumers(tmp.path(), "@angular/core");
        assert_eq!(consumers, vec!["@wildmason/aegis"]);
    }

    #[test]
    fn find_peer_dep_consumers_combines_flat_and_virtual_store() {
        // A pnpm-style hybrid: top-level symlinks/installs at
        // node_modules/foo/ AND the real installs in .pnpm/. Both
        // should be searched, results combined and deduped.
        let tmp = tempfile::tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        // Flat: top-level direct dep
        std::fs::create_dir_all(nm.join("lucide-angular")).unwrap();
        std::fs::write(
            nm.join("lucide-angular").join("package.json"),
            r#"{"name":"lucide-angular","peerDependencies":{"@angular/core":">=21"}}"#,
        )
        .unwrap();
        // Virtual store: transitive consumer not hoisted to top
        let virt = nm
            .join(".pnpm")
            .join("@ngrx+store@21.0.0_@angular+core@21.0.0")
            .join("node_modules")
            .join("@ngrx")
            .join("store");
        std::fs::create_dir_all(&virt).unwrap();
        std::fs::write(
            virt.join("package.json"),
            r#"{"name":"@ngrx/store","peerDependencies":{"@angular/core":">=21"}}"#,
        )
        .unwrap();
        let consumers = find_peer_dep_consumers(tmp.path(), "@angular/core");
        assert_eq!(consumers, vec!["@ngrx/store", "lucide-angular"]);
    }

    #[test]
    fn find_peer_dep_consumers_ignores_pnpm_entries_without_inner_node_modules() {
        // Some pnpm temp/cache entries inside .pnpm/ don't have the
        // expected node_modules/ middle layer. They must be skipped
        // gracefully — no crash, no false positives.
        let tmp = tempfile::tempdir().unwrap();
        let stray = tmp.path().join("node_modules").join(".pnpm").join("stray");
        std::fs::create_dir_all(&stray).unwrap();
        std::fs::write(
            stray.join("package.json"),
            r#"{"name":"stray","peerDependencies":{"@angular/core":">=21"}}"#,
        )
        .unwrap();
        let consumers = find_peer_dep_consumers(tmp.path(), "@angular/core");
        assert!(consumers.is_empty(), "got: {consumers:?}");
    }

    #[test]
    fn widen_cohort_tiers_promotes_compatible_member_to_breaking_when_lockstep_partner_is_breaking()
    {
        let mut breaking = sample_proposal("@angular/core");
        breaking.bump_tier = BumpTier::Breaking;
        breaking.cohort = Some("angular-framework".into());
        let mut compatible = sample_proposal("@angular/common");
        compatible.bump_tier = BumpTier::Compatible;
        compatible.cohort = Some("angular-framework".into());
        let mut proposals = vec![breaking, compatible];

        widen_cohort_tiers(&mut proposals);

        let common = proposals
            .iter()
            .find(|p| p.subject == "@angular/common")
            .unwrap();
        let core = proposals
            .iter()
            .find(|p| p.subject == "@angular/core")
            .unwrap();
        assert_eq!(
            common.bump_tier,
            BumpTier::Breaking,
            "@angular/common should be widened to Breaking to lockstep with @angular/core"
        );
        assert_eq!(
            core.bump_tier,
            BumpTier::Breaking,
            "@angular/core retains its original Breaking tier (no downgrade)"
        );
        assert!(
            common
                .notes
                .iter()
                .any(|n| n.contains("cohort-lockstep") && n.contains("compatible to breaking")),
            "widened proposal should record a cohort-lockstep note; got: {:?}",
            common.notes
        );
        assert!(
            !core.notes.iter().any(|n| n.contains("cohort-lockstep")),
            "unwidened (already-at-max) members must not get a widening note; got: {:?}",
            core.notes
        );
    }

    #[test]
    fn widen_cohort_tiers_skips_single_member_cohorts() {
        // Only one @angular/core proposal in the run — nothing to
        // lockstep with, so no widening note even though it's
        // tagged with a cohort.
        let mut alone = sample_proposal("@angular/core");
        alone.bump_tier = BumpTier::Compatible;
        alone.cohort = Some("angular-framework".into());
        let mut proposals = vec![alone];

        widen_cohort_tiers(&mut proposals);

        let core = &proposals[0];
        assert_eq!(core.bump_tier, BumpTier::Compatible);
        assert!(
            !core.notes.iter().any(|n| n.contains("cohort-lockstep")),
            "single-member cohort must not trigger a widening note; got: {:?}",
            core.notes
        );
    }

    #[test]
    fn widen_cohort_tiers_promotes_lockfile_only_to_compatible_when_partner_is_compatible() {
        // The dominant tier in a 2-member cohort is Compatible —
        // the LockfileOnly member widens to Compatible, but the
        // Compatible member is unchanged.
        let mut lf = sample_proposal("@angular/core");
        lf.bump_tier = BumpTier::LockfileOnly;
        lf.cohort = Some("angular-framework".into());
        let mut compat = sample_proposal("@angular/common");
        compat.bump_tier = BumpTier::Compatible;
        compat.cohort = Some("angular-framework".into());
        let mut proposals = vec![lf, compat];

        widen_cohort_tiers(&mut proposals);

        let core = proposals
            .iter()
            .find(|p| p.subject == "@angular/core")
            .unwrap();
        assert_eq!(core.bump_tier, BumpTier::Compatible);
    }

    #[test]
    fn widen_cohort_tiers_isolates_separate_cohorts() {
        // Two independent cohorts in the same run. Widening must
        // only happen within a cohort — the lodash proposal (no
        // cohort) is left alone, and the @tiptap/* breaking bump
        // does NOT propagate to @angular/*.
        let mut angular_a = sample_proposal("@angular/core");
        angular_a.bump_tier = BumpTier::LockfileOnly;
        angular_a.cohort = Some("angular-framework".into());
        let mut angular_b = sample_proposal("@angular/common");
        angular_b.bump_tier = BumpTier::LockfileOnly;
        angular_b.cohort = Some("angular-framework".into());
        let mut tiptap_a = sample_proposal("@tiptap/core");
        tiptap_a.bump_tier = BumpTier::Breaking;
        tiptap_a.cohort = Some("tiptap".into());
        let mut tiptap_b = sample_proposal("@tiptap/starter-kit");
        tiptap_b.bump_tier = BumpTier::Compatible;
        tiptap_b.cohort = Some("tiptap".into());
        let mut lodash = sample_proposal("lodash");
        lodash.bump_tier = BumpTier::Compatible;
        let mut proposals = vec![angular_a, angular_b, tiptap_a, tiptap_b, lodash];

        widen_cohort_tiers(&mut proposals);

        let by_subject: std::collections::BTreeMap<_, _> = proposals
            .iter()
            .map(|p| (p.subject.as_str(), p.bump_tier))
            .collect();
        // Angular cohort: both stay LockfileOnly (no member above
        // that tier).
        assert_eq!(
            by_subject.get("@angular/core").copied(),
            Some(BumpTier::LockfileOnly)
        );
        assert_eq!(
            by_subject.get("@angular/common").copied(),
            Some(BumpTier::LockfileOnly)
        );
        // Tiptap cohort: the Compatible member widens to Breaking.
        assert_eq!(
            by_subject.get("@tiptap/starter-kit").copied(),
            Some(BumpTier::Breaking)
        );
        assert_eq!(
            by_subject.get("@tiptap/core").copied(),
            Some(BumpTier::Breaking)
        );
        // Cohort-free proposal: untouched.
        assert_eq!(
            by_subject.get("lodash").copied(),
            Some(BumpTier::Compatible)
        );
    }

    #[test]
    fn widen_cohort_tiers_is_idempotent() {
        // Running widening twice must produce the same proposal
        // set — no duplicate notes, no further mutations.
        let mut breaking = sample_proposal("@angular/core");
        breaking.bump_tier = BumpTier::Breaking;
        breaking.cohort = Some("angular-framework".into());
        let mut compatible = sample_proposal("@angular/common");
        compatible.bump_tier = BumpTier::Compatible;
        compatible.cohort = Some("angular-framework".into());
        let mut proposals = vec![breaking, compatible];

        widen_cohort_tiers(&mut proposals);
        let notes_after_first = proposals
            .iter()
            .find(|p| p.subject == "@angular/common")
            .unwrap()
            .notes
            .clone();
        widen_cohort_tiers(&mut proposals);
        let notes_after_second = &proposals
            .iter()
            .find(|p| p.subject == "@angular/common")
            .unwrap()
            .notes;
        assert_eq!(
            &notes_after_first, notes_after_second,
            "second pass must not append duplicate widening notes"
        );
    }

    #[test]
    fn tag_proposals_with_cohorts_assigns_angular_framework_cohort() {
        let mut proposals = vec![
            sample_proposal("@angular/core"),
            sample_proposal("@angular/common"),
            sample_proposal("@angular/cdk"),
            sample_proposal("lodash"),
        ];
        tag_proposals_with_cohorts(&mut proposals);
        let by_subject: std::collections::BTreeMap<_, _> = proposals
            .iter()
            .map(|p| (p.subject.as_str(), p.cohort.as_deref()))
            .collect();
        assert_eq!(
            by_subject.get("@angular/core").copied().flatten(),
            Some("angular-framework")
        );
        assert_eq!(
            by_subject.get("@angular/common").copied().flatten(),
            Some("angular-framework")
        );
        assert_eq!(
            by_subject.get("@angular/cdk").copied().flatten(),
            Some("angular-components")
        );
        assert_eq!(by_subject.get("lodash").copied().flatten(), None);
    }

    #[test]
    fn annotate_proposals_with_overrides_marks_pinned_packages() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{
                "name": "demo",
                "dependencies": { "lodash": "^4.17.0", "axios": "^1.6.0" },
                "overrides": { "lodash": "4.17.21" }
            }"#,
        )
        .unwrap();
        let mut proposals = vec![sample_proposal("lodash"), sample_proposal("axios")];
        annotate_proposals_with_overrides(&mut proposals, tmp.path());
        let lodash = proposals.iter().find(|p| p.subject == "lodash").unwrap();
        let axios = proposals.iter().find(|p| p.subject == "axios").unwrap();
        assert!(
            lodash
                .notes
                .iter()
                .any(|n| n.contains("override-pinned to 4.17.21")),
            "lodash should be annotated; notes: {:?}",
            lodash.notes
        );
        assert!(
            axios.notes.is_empty(),
            "axios should NOT be annotated; notes: {:?}",
            axios.notes
        );
    }

    #[test]
    fn annotate_proposals_picks_up_pnpm_overrides() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{
                "name": "demo",
                "pnpm": { "overrides": { "lodash": "4.17.21" } }
            }"#,
        )
        .unwrap();
        let mut proposals = vec![sample_proposal("lodash")];
        annotate_proposals_with_overrides(&mut proposals, tmp.path());
        assert!(
            proposals[0]
                .notes
                .iter()
                .any(|n| n.contains("override-pinned"))
        );
    }

    #[test]
    fn annotate_proposals_picks_up_yarn_resolutions() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{
                "name": "demo",
                "resolutions": { "lodash": "4.17.21" }
            }"#,
        )
        .unwrap();
        let mut proposals = vec![sample_proposal("lodash")];
        annotate_proposals_with_overrides(&mut proposals, tmp.path());
        assert!(
            proposals[0]
                .notes
                .iter()
                .any(|n| n.contains("override-pinned"))
        );
    }

    #[test]
    fn override_key_to_package_name_handles_path_form() {
        // npm's `"foo > bar"` syntax means "pin `bar` when reached
        // via `foo`." The right-most segment is the pinned package.
        assert_eq!(override_key_to_package_name("foo > bar"), "bar");
        assert_eq!(override_key_to_package_name("a > b > c"), "c");
        assert_eq!(override_key_to_package_name("lodash"), "lodash");
        assert_eq!(
            override_key_to_package_name("@angular/core"),
            "@angular/core"
        );
    }

    #[test]
    fn annotate_proposals_handles_missing_package_json_gracefully() {
        // A scan with no manifest must not crash; the proposals
        // come back unannotated.
        let tmp = tempfile::tempdir().unwrap();
        let mut proposals = vec![sample_proposal("lodash")];
        annotate_proposals_with_overrides(&mut proposals, tmp.path());
        assert!(proposals[0].notes.is_empty());
    }

    #[test]
    fn build_npm_proposals_id_disambiguates_by_source_version() {
        // Two `npm outdated` rows for the same package at different
        // currently-installed versions must produce distinct proposal
        // IDs so a downstream apply-pr branch-per-proposal flow doesn't
        // collide. Same shape as the cargo multi-version transitive
        // case that surfaced in helm/mortar dogfood.
        let manifest_paths = vec![PathBuf::from("package.json")];
        let row_a = NpmOutdatedRow {
            name: "left-pad".into(),
            current: Some("1.0.0".into()),
            wanted: "1.0.0".into(),
            latest: "1.3.0".into(),
        };
        let row_b = NpmOutdatedRow {
            name: "left-pad".into(),
            current: Some("1.1.0".into()),
            wanted: "1.1.0".into(),
            latest: "1.3.0".into(),
        };
        let p_a = build_npm_proposals(&[row_a], &manifest_paths);
        let p_b = build_npm_proposals(&[row_b], &manifest_paths);
        assert_eq!(p_a.len(), 1);
        assert_eq!(p_b.len(), 1);
        assert_ne!(
            p_a[0].id, p_b[0].id,
            "different `from` versions must produce distinct proposal IDs"
        );
        assert!(
            p_a[0].id.contains("1-0-0") && p_a[0].id.contains("to-1-3-0"),
            "expected from-1-0-0 + to-1-3-0 segments: id={}",
            p_a[0].id
        );
    }

    fn sample_proposal(name: &str) -> Proposal {
        Proposal {
            id: format!("npm-{name}-test"),
            ecosystem: EcosystemName::Npm.as_str().into(),
            kind: ProposalKind::Version,
            subject: name.into(),
            from: "1.0.0".into(),
            to: "1.5.0".into(),
            initial_classification: Classification::Exact,
            manifest_paths: vec![],
            notes: vec![],
            bump_tier: BumpTier::Compatible,
            affected_consumers: Vec::new(),
            explanation: None,
            cohort: None,
        }
    }

    // -------------------------------------------------------------------------
    // Workspace member discovery (npm/yarn `workspaces`, pnpm-workspace.yaml,
    // glob expansion).
    // -------------------------------------------------------------------------

    fn proposal_for_subject(subject: &str) -> Proposal {
        Proposal {
            id: format!("npm-{subject}-test"),
            ecosystem: EcosystemName::Npm.as_str().into(),
            kind: ProposalKind::Version,
            subject: subject.into(),
            from: "1.0.0".into(),
            to: "1.5.0".into(),
            initial_classification: Classification::Exact,
            manifest_paths: vec![],
            notes: vec![],
            bump_tier: BumpTier::Compatible,
            affected_consumers: Vec::new(),
            explanation: None,
            cohort: None,
        }
    }

    fn write_pkg(path: &Path, json: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, json).unwrap();
    }

    #[test]
    fn detect_workspace_members_returns_empty_for_single_project() {
        let tmp = tempfile::tempdir().unwrap();
        write_pkg(
            &tmp.path().join("package.json"),
            r#"{"name":"single","version":"1.0.0"}"#,
        );
        let members = detect_workspace_members(tmp.path()).unwrap();
        assert!(
            members.is_empty(),
            "no workspaces field → no members: {members:?}"
        );
    }

    #[test]
    fn detect_workspace_members_reads_literal_workspaces_array() {
        let tmp = tempfile::tempdir().unwrap();
        write_pkg(
            &tmp.path().join("package.json"),
            r#"{
                "name":"root",
                "workspaces":["packages/foo","packages/bar"]
            }"#,
        );
        write_pkg(
            &tmp.path().join("packages/foo/package.json"),
            r#"{"name":"@scope/foo","version":"1.0.0"}"#,
        );
        write_pkg(
            &tmp.path().join("packages/bar/package.json"),
            r#"{"name":"@scope/bar","version":"1.0.0"}"#,
        );
        let members = detect_workspace_members(tmp.path()).unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].name, "@scope/bar");
        assert_eq!(members[1].name, "@scope/foo");
        assert_eq!(
            members[0].relative_path,
            PathBuf::from("packages").join("bar")
        );
    }

    #[test]
    fn detect_workspace_members_reads_object_form_with_packages_key() {
        let tmp = tempfile::tempdir().unwrap();
        write_pkg(
            &tmp.path().join("package.json"),
            r#"{
                "name":"root",
                "workspaces":{"packages":["apps/web","apps/api"]}
            }"#,
        );
        write_pkg(
            &tmp.path().join("apps/web/package.json"),
            r#"{"name":"web"}"#,
        );
        write_pkg(
            &tmp.path().join("apps/api/package.json"),
            r#"{"name":"api"}"#,
        );
        let members = detect_workspace_members(tmp.path()).unwrap();
        let names: Vec<&str> = members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["api", "web"]);
    }

    #[test]
    fn detect_workspace_members_expands_glob_patterns() {
        let tmp = tempfile::tempdir().unwrap();
        write_pkg(
            &tmp.path().join("package.json"),
            r#"{"name":"root","workspaces":["packages/*"]}"#,
        );
        for name in ["alpha", "beta", "gamma"] {
            write_pkg(
                &tmp.path().join("packages").join(name).join("package.json"),
                &format!(r#"{{"name":"{name}"}}"#),
            );
        }
        // A non-package directory mixed in must NOT be reported.
        std::fs::create_dir_all(tmp.path().join("packages/scripts")).unwrap();
        let members = detect_workspace_members(tmp.path()).unwrap();
        let names: Vec<&str> = members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn detect_workspace_members_reads_pnpm_workspace_yaml() {
        let tmp = tempfile::tempdir().unwrap();
        // pnpm doesn't use `workspaces` in package.json — only the YAML.
        write_pkg(&tmp.path().join("package.json"), r#"{"name":"root"}"#);
        std::fs::write(
            tmp.path().join("pnpm-workspace.yaml"),
            "packages:\n  - 'libs/*'\n  - apps/dashboard\n",
        )
        .unwrap();
        for name in ["a", "b"] {
            write_pkg(
                &tmp.path().join("libs").join(name).join("package.json"),
                &format!(r#"{{"name":"@libs/{name}"}}"#),
            );
        }
        write_pkg(
            &tmp.path().join("apps/dashboard/package.json"),
            r#"{"name":"dashboard"}"#,
        );
        let members = detect_workspace_members(tmp.path()).unwrap();
        let names: Vec<&str> = members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["dashboard", "@libs/a", "@libs/b"]);
    }

    #[test]
    fn detect_workspace_members_honors_negation_patterns() {
        // pnpm supports `!packages/private` to exclude from a positive
        // glob match. After positive expansion + negation subtraction,
        // only the non-negated members should remain.
        let tmp = tempfile::tempdir().unwrap();
        write_pkg(&tmp.path().join("package.json"), r#"{"name":"root"}"#);
        std::fs::write(
            tmp.path().join("pnpm-workspace.yaml"),
            "packages:\n  - 'packages/*'\n  - '!packages/private'\n",
        )
        .unwrap();
        for name in ["public", "private"] {
            write_pkg(
                &tmp.path().join("packages").join(name).join("package.json"),
                &format!(r#"{{"name":"{name}"}}"#),
            );
        }
        let members = detect_workspace_members(tmp.path()).unwrap();
        let names: Vec<&str> = members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["public"], "negation should exclude private");
    }

    #[test]
    fn detect_workspace_members_honors_glob_negation_patterns() {
        // Negation works with globs too: `!packages/private-*` should
        // drop every match of that glob even though the positive
        // `packages/*` would otherwise include them.
        let tmp = tempfile::tempdir().unwrap();
        write_pkg(&tmp.path().join("package.json"), r#"{"name":"root"}"#);
        std::fs::write(
            tmp.path().join("pnpm-workspace.yaml"),
            "packages:\n  - 'packages/*'\n  - '!packages/private-*'\n",
        )
        .unwrap();
        for name in ["public", "private-foo", "private-bar", "shared"] {
            write_pkg(
                &tmp.path().join("packages").join(name).join("package.json"),
                &format!(r#"{{"name":"{name}"}}"#),
            );
        }
        let members = detect_workspace_members(tmp.path()).unwrap();
        let names: Vec<&str> = members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["public", "shared"]);
    }

    #[test]
    fn detect_workspace_members_skips_directories_without_package_json() {
        let tmp = tempfile::tempdir().unwrap();
        write_pkg(
            &tmp.path().join("package.json"),
            r#"{"name":"root","workspaces":["packages/*"]}"#,
        );
        std::fs::create_dir_all(tmp.path().join("packages/empty")).unwrap();
        write_pkg(
            &tmp.path().join("packages/real/package.json"),
            r#"{"name":"real"}"#,
        );
        let members = detect_workspace_members(tmp.path()).unwrap();
        let names: Vec<&str> = members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["real"]);
    }

    // -------------------------------------------------------------------------
    // affected_consumers (Resolver — plan §C.3.5 for npm/yarn/pnpm)
    // -------------------------------------------------------------------------

    fn make_workspace(tmp: &tempfile::TempDir, deps_per_member: &[(&str, &str, &str)]) {
        // `deps_per_member` is (member_dir, member_name, dep_block_json).
        // Root declares packages/* as workspaces.
        write_pkg(
            &tmp.path().join("package.json"),
            r#"{"name":"root","workspaces":["packages/*"]}"#,
        );
        for (dir, name, dep_block) in deps_per_member {
            write_pkg(
                &tmp.path().join("packages").join(dir).join("package.json"),
                &format!(r#"{{"name":"{name}",{dep_block}}}"#),
            );
        }
    }

    #[test]
    fn affected_consumers_lists_members_that_directly_declare_dep() {
        let tmp = tempfile::tempdir().unwrap();
        make_workspace(
            &tmp,
            &[
                ("a", "@scope/a", r#""dependencies":{"lodash":"^4.0.0"}"#),
                ("b", "@scope/b", r#""dependencies":{"axios":"^1.0.0"}"#),
                ("c", "@scope/c", r#""dependencies":{"lodash":"^4.0.0"}"#),
            ],
        );
        let eco = NpmEcosystem;
        let consumers = eco
            .affected_consumers(&proposal_for_subject("lodash"), tmp.path())
            .unwrap();
        assert_eq!(consumers, vec!["@scope/a", "@scope/c"]);
    }

    #[test]
    fn affected_consumers_returns_empty_when_no_member_consumes_dep() {
        let tmp = tempfile::tempdir().unwrap();
        make_workspace(
            &tmp,
            &[("a", "@scope/a", r#""dependencies":{"axios":"^1.0.0"}"#)],
        );
        let eco = NpmEcosystem;
        let consumers = eco
            .affected_consumers(&proposal_for_subject("nowhere-pkg"), tmp.path())
            .unwrap();
        assert!(consumers.is_empty());
    }

    #[test]
    fn affected_consumers_excludes_self_when_target_is_workspace_member() {
        // A workspace member named `lodash` is the bumped package, not
        // its own consumer — matches cargo's affected_consumers semantics.
        let tmp = tempfile::tempdir().unwrap();
        make_workspace(
            &tmp,
            &[
                ("a", "@scope/a", r#""dependencies":{"lodash":"^4.0.0"}"#),
                ("b", "lodash", r#""version":"1.0.0""#),
            ],
        );
        let eco = NpmEcosystem;
        let consumers = eco
            .affected_consumers(&proposal_for_subject("lodash"), tmp.path())
            .unwrap();
        assert_eq!(consumers, vec!["@scope/a"]);
    }

    #[test]
    fn affected_consumers_walks_dev_peer_optional_deps() {
        let tmp = tempfile::tempdir().unwrap();
        make_workspace(
            &tmp,
            &[
                ("a", "@scope/a", r#""devDependencies":{"jest":"^29.0.0"}"#),
                ("b", "@scope/b", r#""peerDependencies":{"jest":"^29.0.0"}"#),
                (
                    "c",
                    "@scope/c",
                    r#""optionalDependencies":{"jest":"^29.0.0"}"#,
                ),
                ("d", "@scope/d", r#""dependencies":{"axios":"^1.0.0"}"#),
            ],
        );
        let eco = NpmEcosystem;
        let consumers = eco
            .affected_consumers(&proposal_for_subject("jest"), tmp.path())
            .unwrap();
        assert_eq!(
            consumers,
            vec!["@scope/a", "@scope/b", "@scope/c"],
            "every dep-shaped declaration counts"
        );
    }

    // -------------------------------------------------------------------------
    // update_package_json_constraint — workspace + glob integration
    // -------------------------------------------------------------------------

    #[test]
    fn update_constraint_widens_every_glob_resolved_member() {
        let tmp = tempfile::tempdir().unwrap();
        write_pkg(
            &tmp.path().join("package.json"),
            r#"{"name":"root","workspaces":["packages/*"],"dependencies":{"lodash":"^4.17.0"}}"#,
        );
        for name in ["alpha", "beta"] {
            write_pkg(
                &tmp.path().join("packages").join(name).join("package.json"),
                &format!(r#"{{"name":"{name}","dependencies":{{"lodash":"^4.17.0"}}}}"#),
            );
        }
        let modified = update_package_json_constraint(tmp.path(), "lodash", "4.18.1").unwrap();
        let mut expected = vec![
            PathBuf::from("package.json"),
            PathBuf::from("packages").join("alpha").join("package.json"),
            PathBuf::from("packages").join("beta").join("package.json"),
        ];
        expected.sort();
        assert_eq!(modified, expected);
        for path in &expected {
            let text = std::fs::read_to_string(tmp.path().join(path)).unwrap();
            assert!(
                text.contains("\"^4.18.1\""),
                "every package.json should have the widened constraint: {path:?}"
            );
        }
    }

    #[test]
    fn update_constraint_skips_members_without_the_dep() {
        let tmp = tempfile::tempdir().unwrap();
        write_pkg(
            &tmp.path().join("package.json"),
            r#"{"name":"root","workspaces":["packages/*"]}"#,
        );
        write_pkg(
            &tmp.path().join("packages/has/package.json"),
            r#"{"name":"has","dependencies":{"lodash":"^4.17.0"}}"#,
        );
        write_pkg(
            &tmp.path().join("packages/missing/package.json"),
            r#"{"name":"missing","dependencies":{"axios":"^1.0.0"}}"#,
        );
        let modified = update_package_json_constraint(tmp.path(), "lodash", "4.18.1").unwrap();
        assert_eq!(
            modified,
            vec![PathBuf::from("packages").join("has").join("package.json")]
        );
    }
}
