//! Workspace dep-graph resolution: given a `Proposal`, return the
//! workspace members that consume the bumped crate.
//!
//! Used by `CargoEcosystem::affected_consumers` to drive per-consumer
//! reporting. Internally uses [`cargo_metadata`] against the prepared
//! tree's `Cargo.toml`, with `--all-features` so optional/feature-gated
//! deps don't get silently dropped.

use std::path::Path;

use crate::error::{Error, Result};
use crate::model::{ConsumerId, Proposal};

/// Resolve which workspace members consume the bumped crate. Returns
/// sorted, deduped names of members that reach a package matching
/// `proposal.subject` via the cargo dependency graph.
///
/// Returns an empty `Vec` when the bumped crate isn't in the dep graph
/// at all (e.g. the workspace doesn't consume it after all). Failures
/// (`cargo metadata` errors, missing Cargo.toml) propagate.
///
/// This is the Resolver stage from plan §C.3.5: per-proposal
/// workspace-member dep-graph filtering so the Reporter can produce
/// per-consumer rows for only members that actually use the bumped
/// crate. The plan's pipeline runs the Resolver after Applier (so the
/// post-apply `Cargo.lock` is what's resolved), but for the trait-method
/// surface we just run against whatever tree is passed in.
pub(super) fn resolve_cargo_consumers(
    proposal: &Proposal,
    tree: &Path,
) -> Result<Vec<ConsumerId>> {
    use cargo_metadata::{CargoOpt, MetadataCommand};

    let manifest_path = tree.join("Cargo.toml");
    if !manifest_path.is_file() {
        return Err(Error::InvalidManifest {
            path: manifest_path,
            message: "Cargo.toml not found in tree (cargo metadata cannot resolve)".into(),
        });
    }

    // `--all-features` so optional deps appear in the resolve graph. The
    // blast-radius signal is "which workspace members are affected if I
    // merge this bump" — that has to include feature-gated consumers,
    // because the bump applies regardless of which feature flags any
    // individual CI run happens to exercise. Default `cargo metadata`
    // resolves only default features and silently drops optional deps.
    let metadata = MetadataCommand::new()
        .manifest_path(&manifest_path)
        .features(CargoOpt::AllFeatures)
        .exec()
        .map_err(|e| Error::other(format!("cargo metadata failed: {e}")))?;

    Ok(find_workspace_consumers_in_metadata(
        &metadata,
        &proposal.subject,
    ))
}

/// Pure graph-walk helper: given parsed `cargo metadata` output and a
/// target crate name, return the names of workspace members that reach
/// the target through any transitive dependency edge.
///
/// Split out from `resolve_cargo_consumers` so the graph-walking logic
/// can be exercised against real `cargo metadata` output from synthetic
/// workspace fixtures without intermediating constructors.
pub(super) fn find_workspace_consumers_in_metadata(
    metadata: &cargo_metadata::Metadata,
    target_name: &str,
) -> Vec<ConsumerId> {
    use std::collections::{HashMap, HashSet};

    // Collect every PackageId whose name matches the target. Multiple
    // versions of the same crate produce multiple matching IDs — any one
    // suffices for reachability.
    let target_ids: HashSet<&cargo_metadata::PackageId> = metadata
        .packages
        .iter()
        .filter(|p| p.name == target_name)
        .map(|p| &p.id)
        .collect();

    if target_ids.is_empty() {
        return Vec::new();
    }

    let Some(resolve) = &metadata.resolve else {
        return Vec::new();
    };

    // Build adjacency: PackageId -> resolved dep PackageIds.
    let dep_graph: HashMap<&cargo_metadata::PackageId, &[cargo_metadata::PackageId]> = resolve
        .nodes
        .iter()
        .map(|n| (&n.id, n.dependencies.as_slice()))
        .collect();

    // For each workspace member, BFS to determine if any target is
    // reachable. The set of reachable nodes from each member is small in
    // practice; we don't memoize across members for v1 simplicity.
    let mut consumers: Vec<ConsumerId> = Vec::new();
    for member_id in &metadata.workspace_members {
        // A crate doesn't consume itself — if a workspace member IS the
        // bumped target, skip it. The Reporter renders the bumped crate
        // as the proposal row; consumers are the OTHER members affected.
        if target_ids.contains(member_id) {
            continue;
        }
        if can_reach_any(member_id, &target_ids, &dep_graph)
            && let Some(pkg) = metadata.packages.iter().find(|p| &p.id == member_id)
        {
            consumers.push(pkg.name.clone());
        }
    }
    consumers.sort();
    consumers.dedup();
    consumers
}

fn can_reach_any(
    start: &cargo_metadata::PackageId,
    targets: &std::collections::HashSet<&cargo_metadata::PackageId>,
    graph: &std::collections::HashMap<&cargo_metadata::PackageId, &[cargo_metadata::PackageId]>,
) -> bool {
    use std::collections::HashSet;

    let mut visited: HashSet<&cargo_metadata::PackageId> = HashSet::new();
    let mut queue: Vec<&cargo_metadata::PackageId> = vec![start];
    while let Some(pid) = queue.pop() {
        if !visited.insert(pid) {
            continue;
        }
        if targets.contains(pid) {
            return true;
        }
        if let Some(deps) = graph.get(pid) {
            for d in deps.iter() {
                queue.push(d);
            }
        }
    }
    false
}
