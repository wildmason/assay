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
//! which the proposer parses via [`parse_yarn1_outdated_output`]. The
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
    /// `yarn.lock` — recognized but not actionable in v1 (different
    /// `yarn outdated --json` format).
    Yarn,
}

impl NpmFlavor {
    fn lockfile_name(self) -> &'static str {
        match self {
            NpmFlavor::Npm => "package-lock.json",
            NpmFlavor::Pnpm => "pnpm-lock.yaml",
            NpmFlavor::Yarn => "yarn.lock",
        }
    }
}

fn detect_flavor(repo: &Path) -> Option<NpmFlavor> {
    [NpmFlavor::Npm, NpmFlavor::Pnpm, NpmFlavor::Yarn]
        .into_iter()
        .find(|flavor| repo.join(flavor.lockfile_name()).is_file())
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
        if package_json.is_file() {
            found.push(Manifest {
                path: PathBuf::from("package.json"),
                kind: ManifestKind::PackageJson,
                metadata: BTreeMap::new(),
            });
        }
        if let Some(flavor) = detect_flavor(repo) {
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
        _ctx: &EcosystemContext,
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
        run_npm_proposer(flavor, repo, &manifest_paths)
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
    /// Highest version that satisfies the current constraint.
    wanted: String,
    /// Most recent publish on the registry.
    latest: String,
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
        rows.push(NpmOutdatedRow {
            name,
            current: entry.current,
            wanted: entry.wanted,
            latest: entry.latest,
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
            "npm-{}-{}",
            sanitize_id_segment(&row.name),
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
    let args: &[&str] = match flavor {
        NpmFlavor::Npm => &["outdated", "--json"],
        NpmFlavor::Pnpm => &["outdated", "--format=json"],
        NpmFlavor::Yarn => &["outdated", "--json"],
    };

    let mut cmd = std::process::Command::new(bin);
    cmd.args(args).current_dir(repo);
    let run =
        run_with_timeout(cmd, std::time::Duration::from_secs(120)).map_err(|source| Error::Io {
            path: repo.to_path_buf(),
            source,
        })?;
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
    let bin = npm_binary_name(flavor);
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
    };
    let package_json = tree_path.join("package.json");
    let snapshot = std::fs::read(&package_json).map_err(|source| Error::Io {
        path: package_json.clone(),
        source,
    })?;
    let mut cmd = std::process::Command::new(bin);
    cmd.args(&args).current_dir(tree_path);
    let install_result = run_install_with_timeout(cmd, bin, tree_path);
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
    let bin = npm_binary_name(flavor);
    let args: &[&str] = match flavor {
        NpmFlavor::Npm => &["install", "--no-audit", "--no-fund"],
        NpmFlavor::Pnpm => &["install"],
        // yarn1: `yarn install` refreshes yarn.lock against the
        // freshly-edited package.json.
        NpmFlavor::Yarn => &["install"],
    };
    let mut cmd = std::process::Command::new(bin);
    cmd.args(args).current_dir(tree_path);
    run_install_with_timeout(cmd, bin, tree_path)
}

fn run_install_with_timeout(cmd: std::process::Command, bin: &str, tree_path: &Path) -> Result<()> {
    let run =
        run_with_timeout(cmd, std::time::Duration::from_secs(300)).map_err(|source| Error::Io {
            path: tree_path.to_path_buf(),
            source,
        })?;
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
                    if entry.is_dir() && entry.join("package.json").is_file() {
                        if let Ok(rel) = entry.strip_prefix(tree_path) {
                            resolved_dirs.insert(rel.to_path_buf());
                        }
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
    Ok(consumers)
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
    if let Some(rest) = existing.strip_prefix('^') {
        if rest.contains(|c: char| c.is_ascii_digit()) {
            return format!("^{new_version}");
        }
    }
    if let Some(rest) = existing.strip_prefix('~') {
        if rest.contains(|c: char| c.is_ascii_digit()) {
            return format!("~{new_version}");
        }
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
        (NpmFlavor::Yarn, _) => "",
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
