//! Framework cohort definitions for npm-ecosystem proposals.
//!
//! A "cohort" is a set of packages that MUST move together to remain
//! self-consistent. Examples: `@angular/core` + `@angular/common` +
//! `@angular/compiler` (all framework members share major+minor on
//! every release; bumping one without the others is guaranteed runtime
//! breakage); `next` + `@next/*`; `vue` + `@vue/*`; `react` +
//! `react-dom`. When a cohort member appears in a run's proposal set,
//! every member in the same cohort is tagged so the validator/applier
//! treat them as one atomic unit and the reporter groups them under
//! one heading.
//!
//! The matcher uses prefix + exact rules — no registry lookups, no
//! peer-dep crawling. That keeps cohort assignment a pure function of
//! the package name, which is fast and reproducible. Frameworks that
//! genuinely don't follow lockstep (e.g. `typescript` ecosystem,
//! `@types/*`, `eslint` + `@eslint/*` with the v9 split) are
//! deliberately left as stand-alone proposals.
//!
//! Adding a new cohort: extend [`KNOWN_COHORTS`] below. Tests at the
//! bottom of this module cover the matcher's exact-vs-prefix
//! disambiguation.

/// Identifier for one framework cohort. Stable across releases — used
/// in `Proposal.cohort` and surfaced in receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CohortDef {
    /// Stable cohort id (kebab-case). Doubles as the human-facing
    /// header in the reporter.
    pub id: &'static str,
    /// Display name shown in the reporter (`@angular/* framework`,
    /// `next + @next/*`, etc.).
    pub display: &'static str,
    /// Exact package names that belong to this cohort. Case-sensitive.
    pub exact: &'static [&'static str],
    /// Scope prefixes (e.g. `@nuxt/`, `@next/`). Every package whose
    /// name starts with one of these prefixes joins the cohort. The
    /// trailing `/` is required to prevent `@nuxt/` from matching
    /// `@nuxtjs-third-party` etc.
    pub prefixes: &'static [&'static str],
}

/// Known framework cohorts. Order is stable — the first matching
/// entry wins for prefix collisions.
pub const KNOWN_COHORTS: &[CohortDef] = &[
    // @angular/* framework members — must share major+minor on every
    // release. `cdk`/`material` follow a separate cadence (own
    // cohort below). `build`/`cli` are tooling and ride yet another
    // cadence — also their own cohort.
    CohortDef {
        id: "angular-framework",
        display: "@angular/* framework",
        exact: &[
            "@angular/core",
            "@angular/common",
            "@angular/compiler",
            "@angular/compiler-cli",
            "@angular/forms",
            "@angular/platform-browser",
            "@angular/platform-browser-dynamic",
            "@angular/platform-server",
            "@angular/router",
            "@angular/animations",
            "@angular/elements",
            "@angular/service-worker",
            "@angular/upgrade",
            "@angular/localize",
        ],
        prefixes: &[],
    },
    // @angular tooling (build, cli, ssr) — separate release cadence
    // from framework. The dogfood (slate) flagged the
    // framework@21.2.4 vs tooling@21.2.9 version skew.
    CohortDef {
        id: "angular-tooling",
        display: "@angular/* tooling",
        exact: &["@angular/build", "@angular/cli", "@angular/ssr"],
        prefixes: &[],
    },
    // @angular CDK + Material components — share their own cadence.
    CohortDef {
        id: "angular-components",
        display: "@angular/* components",
        exact: &[
            "@angular/cdk",
            "@angular/material",
            "@angular/google-maps",
            "@angular/youtube-player",
            "@angular/material-experimental",
            "@angular/material-moment-adapter",
            "@angular/material-luxon-adapter",
            "@angular/material-date-fns-adapter",
        ],
        prefixes: &[],
    },
    // Tiptap — every extension lives under @tiptap/* and the suite
    // publishes in lockstep. Mixing versions across @tiptap/core +
    // extensions is unsupported.
    CohortDef {
        id: "tiptap",
        display: "@tiptap/*",
        exact: &[],
        prefixes: &["@tiptap/"],
    },
    // Next.js + its sub-scope.
    CohortDef {
        id: "nextjs",
        display: "next + @next/*",
        exact: &["next"],
        prefixes: &["@next/"],
    },
    // Nuxt + sub-scope.
    CohortDef {
        id: "nuxt",
        display: "nuxt + @nuxt/*",
        exact: &["nuxt"],
        prefixes: &["@nuxt/"],
    },
    // SvelteKit ecosystem — @sveltejs/* moves together.
    CohortDef {
        id: "sveltekit",
        display: "@sveltejs/*",
        exact: &[],
        prefixes: &["@sveltejs/"],
    },
    // Astro framework — root + @astrojs/* adapters/integrations.
    CohortDef {
        id: "astro",
        display: "astro + @astrojs/*",
        exact: &["astro"],
        prefixes: &["@astrojs/"],
    },
    // React core trio — react + react-dom + react-test-renderer.
    // Must share major to avoid hooks/runtime mismatches.
    CohortDef {
        id: "react",
        display: "react + react-dom",
        exact: &["react", "react-dom", "react-test-renderer"],
        prefixes: &[],
    },
    // Vue 3 family — @vue/* internals must match the `vue` major.
    CohortDef {
        id: "vue",
        display: "vue + @vue/*",
        exact: &["vue"],
        prefixes: &["@vue/"],
    },
    // Vitest ecosystem.
    CohortDef {
        id: "vitest",
        display: "vitest + @vitest/*",
        exact: &["vitest"],
        prefixes: &["@vitest/"],
    },
    // Storybook ecosystem.
    CohortDef {
        id: "storybook",
        display: "storybook + @storybook/*",
        exact: &["storybook"],
        prefixes: &["@storybook/"],
    },
    // NestJS family.
    CohortDef {
        id: "nestjs",
        display: "@nestjs/*",
        exact: &[],
        prefixes: &["@nestjs/"],
    },
    // Remix family.
    CohortDef {
        id: "remix",
        display: "@remix-run/*",
        exact: &[],
        prefixes: &["@remix-run/"],
    },
    // Tauri JS bindings — @tauri-apps/api + @tauri-apps/plugin-* +
    // @tauri-apps/cli must share major with the cargo-side `tauri`
    // crate. Tagged as a cohort even though the cargo crate isn't
    // an npm dep — the JS-side coupling is real.
    CohortDef {
        id: "tauri-js",
        display: "@tauri-apps/*",
        exact: &[],
        prefixes: &["@tauri-apps/"],
    },
];

/// Find the cohort a given npm package belongs to. Exact-match wins
/// over prefix-match; among prefix matches, the FIRST entry in
/// [`KNOWN_COHORTS`] wins (so put the more-specific cohorts before
/// any catch-all prefix).
pub fn match_cohort(package: &str) -> Option<&'static CohortDef> {
    // Exact match pass — every cohort first.
    KNOWN_COHORTS
        .iter()
        .find(|cohort| cohort.exact.contains(&package))
        .or_else(|| {
            // Prefix-match pass — first hit wins.
            KNOWN_COHORTS
                .iter()
                .find(|cohort| cohort.prefixes.iter().any(|p| package.starts_with(p)))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn angular_core_lands_in_framework_cohort() {
        let c = match_cohort("@angular/core").unwrap();
        assert_eq!(c.id, "angular-framework");
    }

    #[test]
    fn angular_cdk_lands_in_components_cohort_not_framework() {
        let c = match_cohort("@angular/cdk").unwrap();
        assert_eq!(c.id, "angular-components");
    }

    #[test]
    fn angular_cli_lands_in_tooling_cohort() {
        let c = match_cohort("@angular/cli").unwrap();
        assert_eq!(c.id, "angular-tooling");
    }

    #[test]
    fn tiptap_extension_matches_via_prefix() {
        let c = match_cohort("@tiptap/extension-bold").unwrap();
        assert_eq!(c.id, "tiptap");
    }

    #[test]
    fn next_exact_matches_root_package() {
        let c = match_cohort("next").unwrap();
        assert_eq!(c.id, "nextjs");
    }

    #[test]
    fn next_subscope_matches_via_prefix() {
        let c = match_cohort("@next/font").unwrap();
        assert_eq!(c.id, "nextjs");
    }

    #[test]
    fn react_dom_lands_in_react_cohort() {
        let c = match_cohort("react-dom").unwrap();
        assert_eq!(c.id, "react");
    }

    #[test]
    fn unmatched_package_returns_none() {
        assert!(match_cohort("lodash").is_none());
        assert!(match_cohort("@types/node").is_none());
        assert!(match_cohort("typescript").is_none());
    }

    #[test]
    fn lookalike_packages_dont_false_match() {
        // `@nuxtjs-foo` is NOT `@nuxt/...` — the trailing slash on
        // the prefix prevents this.
        assert!(match_cohort("@nuxtjs-foo").is_none());
        // `nextjs-blog` is NOT `next` (exact name has to match).
        assert!(match_cohort("nextjs-blog").is_none());
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
