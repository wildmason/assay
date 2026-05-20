//! Apply + install + copy-back primitives for npm/pnpm/yarn1/berry.
//!
//! Tier-aware: `LockfileOnly` proposals install the explicit target
//! version (with a snapshot/restore wrapper around package.json so the
//! manifest stays byte-identical); `Compatible` / `Breaking` proposals
//! widen the package.json constraint first, then refresh the lockfile.
//! The package.json edit helpers also live here since they're tied to
//! the apply pipeline.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::model::{BumpTier, Proposal};
use crate::process_runner::{RunResult, run_with_timeout};

use super::flavor::{
    NpmFlavor, detect_flavor, flavor_from_binary_name, map_npm_spawn_io, npm_binary_name,
};
use super::workspaces::detect_workspace_members;

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
pub(super) fn apply_npm_proposal(
    flavor: NpmFlavor,
    proposal: &Proposal,
    tree_path: &Path,
) -> Result<()> {
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

pub(super) fn try_edit_package_json(path: &Path, name: &str, new_version: &str) -> Result<bool> {
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
pub(super) fn resolve_install_version(
    tree_path: &Path,
    name: &str,
    new_version: &str,
) -> Result<String> {
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

pub(super) fn preserve_constraint_prefix(existing: &str, new_version: &str) -> String {
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
pub(super) fn copy_back_npm_sandbox(sandbox: &Path, host: &Path) -> Result<Vec<PathBuf>> {
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
