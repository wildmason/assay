//! Crate-family cohort definitions for cargo-ecosystem proposals.
//!
//! The Cargo analog of [`super::npm_cohorts`]. A cohort is a set of
//! crates that MUST move together to remain self-consistent. Cargo
//! families behave differently from npm framework cohorts in that
//! they typically share `^MAJOR.MINOR.0` via `[workspace.dependencies]`
//! and a `cargo update --workspace` bumps all members in lockstep —
//! but bumping ONE family member while leaving siblings behind is
//! exactly the kind of partial-cohort apply that breaks compilation:
//!
//! - `tokio` 1.40 + `tokio-util` 0.7 (paired with `tokio` 1.40) →
//!   bumping `tokio` to 1.45 without updating `tokio-util` leaves
//!   `tokio-util` linking against the wrong `tokio::sync::*` ABI
//!   surface.
//! - `serde` + `serde_derive` MUST share version (they cross-compile
//!   against each other's macro output).
//! - `tracing` + `tracing-core` + `tracing-subscriber` share a
//!   collector/registry contract; mixing majors breaks subscriber
//!   instantiation.
//!
//! Cohort definitions follow the same shape as `npm_cohorts`: stable
//! `id`, human-facing `display`, exact-match list, and scope/prefix
//! list. Cargo crate names are flat (no `@scope/`) so the `prefixes`
//! field uses string prefixes like `"tokio-"` rather than scope
//! delimiters.
//!
//! Adding a new cohort: extend [`KNOWN_COHORTS`] below. Be
//! conservative — only group crates that are *contractually*
//! coupled at the type/ABI level, not crates that merely happen to
//! be maintained by the same org or that appear together in
//! workflows. Loose coupling (e.g. `clap` ↔ `clap_complete`) belongs
//! in a cohort; orthogonal-but-related crates (e.g. `tokio` and
//! `mio`) do NOT.

/// Identifier for one cargo cohort. Same shape as
/// [`super::npm_cohorts::CohortDef`]; kept as a separate type so
/// future ecosystem-specific fields don't bleed across.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CohortDef {
    /// Stable cohort id (kebab-case). Doubles as the human-facing
    /// header in the reporter.
    pub id: &'static str,
    /// Display name shown in the reporter (`tokio + tokio-util`,
    /// `tracing + tracing-*`, etc.).
    pub display: &'static str,
    /// Exact crate names that belong to this cohort. Case-sensitive.
    pub exact: &'static [&'static str],
    /// Crate-name prefixes (e.g. `"tokio-"`, `"tracing-"`). Every
    /// crate whose name starts with one of these prefixes joins the
    /// cohort. Use the trailing hyphen to prevent false matches
    /// like `"tracing"` itself when it's already in `exact`.
    pub prefixes: &'static [&'static str],
}

/// Known cargo crate-family cohorts. Order is stable — the first
/// matching entry wins for prefix collisions, so put more-specific
/// cohorts above any catch-all.
pub const KNOWN_COHORTS: &[CohortDef] = &[
    // Tokio runtime family. Tokio itself + the utility crates
    // (`tokio-util`, `tokio-stream`, `tokio-test`, `tokio-macros`)
    // all cross-compile against the same `tokio` major+minor. The
    // `tokio-rs` org also publishes `tokio-tungstenite`, `tokio-tar`,
    // etc., but those track different cadences and stay out of the
    // cohort to avoid false positives.
    CohortDef {
        id: "tokio",
        display: "tokio + tokio-*",
        exact: &[
            "tokio",
            "tokio-util",
            "tokio-stream",
            "tokio-test",
            "tokio-macros",
            "tokio-io-timeout",
        ],
        prefixes: &[],
    },
    // Serde core + derive — they MUST share version because the
    // derive macro emits code against a specific `serde::Serialize`
    // / `serde::Deserialize` trait shape. `serde_json` /
    // `serde_yaml` / `toml` are separate (they depend on serde but
    // ride their own cadences) — left out deliberately.
    CohortDef {
        id: "serde",
        display: "serde + serde_derive",
        exact: &["serde", "serde_derive"],
        prefixes: &[],
    },
    // Tracing family. tracing + tracing-core + tracing-subscriber
    // share the collector/dispatcher contract; mixing majors
    // breaks subscriber instantiation. tracing-attributes pairs
    // with tracing via the proc-macro contract.
    CohortDef {
        id: "tracing",
        display: "tracing + tracing-*",
        exact: &[
            "tracing",
            "tracing-core",
            "tracing-subscriber",
            "tracing-attributes",
            "tracing-log",
            "tracing-futures",
            "tracing-tower",
            "tracing-opentelemetry",
        ],
        prefixes: &[],
    },
    // Clap family. clap + clap_derive + clap_complete + clap_mangen.
    // The derive crate emits Args/Subcommand impls against the clap
    // major; mixing majors fails to compile.
    CohortDef {
        id: "clap",
        display: "clap + clap_*",
        exact: &[
            "clap",
            "clap_derive",
            "clap_complete",
            "clap_mangen",
            "clap_builder",
            "clap_lex",
            "clap_complete_fig",
            "clap_complete_nushell",
        ],
        prefixes: &[],
    },
    // Axum web framework. axum + axum-core + axum-extra +
    // axum-macros all track the same release cadence and share
    // handler/state types across the API boundary.
    CohortDef {
        id: "axum",
        display: "axum + axum-*",
        exact: &[
            "axum",
            "axum-core",
            "axum-extra",
            "axum-macros",
            "axum-server",
        ],
        prefixes: &[],
    },
    // Tower service middleware family. tower + tower-http +
    // tower-service share `Service` trait + Layer composition
    // contracts; major-skewing them breaks middleware stacks.
    CohortDef {
        id: "tower",
        display: "tower + tower-*",
        exact: &[
            "tower",
            "tower-http",
            "tower-service",
            "tower-layer",
            "tower-test",
        ],
        prefixes: &[],
    },
    // Prost protobuf family. prost + prost-build + prost-types +
    // prost-derive all share message-trait shape.
    CohortDef {
        id: "prost",
        display: "prost + prost-*",
        exact: &[
            "prost",
            "prost-build",
            "prost-types",
            "prost-derive",
            "prost-reflect",
        ],
        prefixes: &[],
    },
    // Hyper HTTP family. hyper + hyper-util + hyper-tls + hyper-rustls.
    // The hyper 1.x split separated `hyper-util` from `hyper` as a
    // hard requirement for the new server/client APIs; they MUST
    // travel together.
    CohortDef {
        id: "hyper",
        display: "hyper + hyper-*",
        exact: &[
            "hyper",
            "hyper-util",
            "hyper-tls",
            "hyper-rustls",
            "hyper-timeout",
        ],
        prefixes: &[],
    },
    // Tonic gRPC family. tonic + tonic-build + tonic-types +
    // tonic-reflection all track the same release. Tonic depends
    // on prost transitively, but prost's separate cohort handles
    // that side.
    CohortDef {
        id: "tonic",
        display: "tonic + tonic-*",
        exact: &[
            "tonic",
            "tonic-build",
            "tonic-types",
            "tonic-reflection",
            "tonic-health",
        ],
        prefixes: &[],
    },
    // Reqwest family — reqwest + reqwest-middleware. These ride
    // related but not identical cadences; keep loosely-coupled
    // siblings out of the cohort.
    CohortDef {
        id: "reqwest",
        display: "reqwest + middleware",
        exact: &["reqwest", "reqwest-middleware"],
        prefixes: &[],
    },
    // Tauri JS-bindings sister of the npm `tauri-js` cohort —
    // applies on the Rust side. tauri + tauri-build + tauri-runtime
    // + tauri-codegen + tauri-utils + tauri-plugin-* family.
    CohortDef {
        id: "tauri",
        display: "tauri + tauri-*",
        exact: &[
            "tauri",
            "tauri-build",
            "tauri-runtime",
            "tauri-runtime-wry",
            "tauri-codegen",
            "tauri-utils",
            "tauri-macros",
        ],
        prefixes: &["tauri-plugin-"],
    },
    // Bevy game-engine family — every official sub-crate ships in
    // lockstep with the main `bevy` crate via the `bevy_internal`
    // umbrella. Inter-crate API drift between minor releases makes
    // partial cohort apply a guaranteed compile break.
    CohortDef {
        id: "bevy",
        display: "bevy + bevy_*",
        exact: &["bevy", "bevy_internal", "bevy_macro_utils"],
        prefixes: &["bevy_"],
    },
];

/// Find the cohort a given cargo crate belongs to. Exact-match wins
/// over prefix-match; among prefix matches, the FIRST entry in
/// [`KNOWN_COHORTS`] wins (so put the more-specific cohorts before
/// any catch-all prefix).
pub fn match_cohort(crate_name: &str) -> Option<&'static CohortDef> {
    KNOWN_COHORTS
        .iter()
        .find(|cohort| cohort.exact.contains(&crate_name))
        .or_else(|| {
            KNOWN_COHORTS
                .iter()
                .find(|cohort| cohort.prefixes.iter().any(|p| crate_name.starts_with(p)))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokio_lands_in_tokio_cohort() {
        let c = match_cohort("tokio").unwrap();
        assert_eq!(c.id, "tokio");
    }

    #[test]
    fn tokio_util_lands_in_tokio_cohort() {
        let c = match_cohort("tokio-util").unwrap();
        assert_eq!(c.id, "tokio");
    }

    #[test]
    fn serde_derive_lands_in_serde_cohort() {
        let c = match_cohort("serde_derive").unwrap();
        assert_eq!(c.id, "serde");
    }

    #[test]
    fn tracing_subscriber_lands_in_tracing_cohort() {
        let c = match_cohort("tracing-subscriber").unwrap();
        assert_eq!(c.id, "tracing");
    }

    #[test]
    fn clap_derive_lands_in_clap_cohort() {
        let c = match_cohort("clap_derive").unwrap();
        assert_eq!(c.id, "clap");
    }

    #[test]
    fn axum_extra_lands_in_axum_cohort() {
        let c = match_cohort("axum-extra").unwrap();
        assert_eq!(c.id, "axum");
    }

    #[test]
    fn tauri_plugin_matches_via_prefix() {
        let c = match_cohort("tauri-plugin-fs").unwrap();
        assert_eq!(c.id, "tauri");
    }

    #[test]
    fn bevy_subcrate_matches_via_prefix() {
        let c = match_cohort("bevy_ecs").unwrap();
        assert_eq!(c.id, "bevy");
    }

    #[test]
    fn unmatched_crate_returns_none() {
        // Crates with related names but not in any cohort:
        assert!(match_cohort("anyhow").is_none());
        assert!(match_cohort("thiserror").is_none());
        // `serde_json` deliberately not in serde cohort — own cadence.
        assert!(match_cohort("serde_json").is_none());
        // `tokio-tungstenite` not in tokio cohort — own cadence.
        assert!(match_cohort("tokio-tungstenite").is_none());
    }

    #[test]
    fn lookalike_crates_dont_false_match() {
        // `tracing-actix-web` is not in the tracing cohort (not in
        // exact list, no prefix match for `"tracing-"`).
        assert!(match_cohort("tracing-actix-web").is_none());
        // `bevy_ecs_tilemap` IS bevy-prefixed — verifies the prefix
        // catches third-party `bevy_*` plugins that happen to follow
        // the prefix convention. This is intentional: third-party
        // bevy plugins typically pin to a bevy version range and
        // benefit from cohort lockstep behavior too.
        let c = match_cohort("bevy_ecs_tilemap").unwrap();
        assert_eq!(c.id, "bevy");
    }

    #[test]
    fn every_cohort_has_a_unique_id() {
        let mut ids = std::collections::BTreeSet::new();
        for c in KNOWN_COHORTS {
            assert!(ids.insert(c.id), "duplicate cohort id: {}", c.id);
        }
    }

    #[test]
    fn every_cohort_has_at_least_one_member_or_prefix() {
        for c in KNOWN_COHORTS {
            assert!(
                !c.exact.is_empty() || !c.prefixes.is_empty(),
                "cohort `{}` has no exact/prefix members",
                c.id
            );
        }
    }
}
