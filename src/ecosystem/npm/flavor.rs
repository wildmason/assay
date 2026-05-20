//! Lockfile-flavor detection (npm / pnpm / yarn1 / yarn berry) plus the
//! platform-aware binary names and spawn-time IO error mapper used by the
//! proposer + applier when shelling out to the matching package manager.

use std::path::Path;

use crate::error::Error;

/// Lockfile flavor the project uses. Determines which `outdated` command
/// the proposer invokes and which lockfile path the copy-back ships.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NpmFlavor {
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
    pub(super) fn lockfile_name(self) -> &'static str {
        match self {
            NpmFlavor::Npm => "package-lock.json",
            NpmFlavor::Pnpm => "pnpm-lock.yaml",
            NpmFlavor::Yarn | NpmFlavor::YarnBerry => "yarn.lock",
        }
    }
}

pub(super) fn detect_flavor(repo: &Path) -> Option<NpmFlavor> {
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
pub(super) fn yarn_lock_is_berry(repo: &Path) -> bool {
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

/// Platform-aware binary name for npm/pnpm. On Windows, the actual
/// executables are `.cmd` shims around node scripts; `Command::new`
/// uses `CreateProcess` which only auto-resolves `.exe`, so we must
/// say `.cmd` explicitly. On Unix the bare name works.
pub(super) fn npm_binary_name(flavor: NpmFlavor) -> &'static str {
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
pub(super) fn flavor_from_binary_name(bin: &str) -> Option<NpmFlavor> {
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
pub(super) fn map_npm_spawn_io(
    source: std::io::Error,
    bin: &str,
    flavor: NpmFlavor,
    repo: &Path,
) -> Error {
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
