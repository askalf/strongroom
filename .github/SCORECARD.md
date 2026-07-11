# OpenSSF Scorecard — hardening setup (reusable template)

This repo is configured to score as high as an actively-maintained, single-org
project can on [OpenSSF Scorecard](https://scorecard.dev). This file documents
what's in place and the exact steps to reproduce it on another repo — copy the
files listed under **Portable files**, then do the two **Operator actions**.

The live badge and score are in the README; the raw data is at
`https://api.scorecard.dev/projects/github.com/<org>/<repo>`.

## Checks already maxed (10/10) by files in this repo

| Check | How |
|---|---|
| Token-Permissions | every workflow declares minimal `permissions:` (top-level `read`, per-job least-privilege) |
| Pinned-Dependencies | every GitHub Action is pinned by full commit SHA; npm deps via committed `package-lock.json` |
| Dangerous-Workflow | no `pull_request_target` + untrusted checkout; no script injection |
| SAST | CodeQL on every push/PR (`codeql.yml`) |
| Dependency-Update-Tool | Dependabot (`dependabot.yml`, npm + actions) |
| Security-Policy | `SECURITY.md` |
| License | `LICENSE` (MIT) |
| CI-Tests | required status checks on all PRs |
| Binary-Artifacts | none committed |
| Vulnerabilities | `npm audit` clean (kept clean — see note under Fuzzing) |
| Packaging | `publish.yml` publishes to npm via OIDC trusted publishing (no long-lived token) |
| Fuzzing | ClusterFuzzLite (`.clusterfuzzlite/` + `cflite.yml`), Jazzer.js targets in `./fuzz` |

## Operator actions (unlock the remaining checks)

These can't be done from code — they need repo-admin / external enrollment:

1. **Branch-Protection** — the scanner's default `GITHUB_TOKEN` can't read
   branch-protection settings, so the check errors out (`-1`). Fix:
   - Create a **fine-grained PAT** scoped to this repo with **`Administration:
     Read`** + **`Metadata: Read`** (a classic PAT with `repo` + `read:org`
     also works).
   - Add it as the repo secret **`SCORECARD_TOKEN`**. `scorecard.yml` already
     references `${{ secrets.SCORECARD_TOKEN || github.token }}`, so it starts
     working the next run and falls back safely if unset.
   - Optionally strengthen the rules (safe for a solo squash-merge flow, raises
     the tier without requiring a second reviewer):
     ```sh
     gh api -X PUT repos/<org>/<repo>/branches/<default>/protection --input - <<'JSON'
     { "required_status_checks": { "strict": true, "contexts": ["<your CI contexts>"] },
       "enforce_admins": false, "required_pull_request_reviews": null, "restrictions": null,
       "required_linear_history": true, "allow_force_pushes": false, "allow_deletions": false,
       "required_conversation_resolution": true }
     JSON
     ```

2. **CII-Best-Practices** — self-certification badge. Enroll the project at
   <https://www.bestpractices.dev>, complete the questionnaire (this repo already
   satisfies the "passing" criteria: version control, unique version numbers,
   CHANGELOG, reporting process in `SECURITY.md`, HTTPS, tests, CI, static
   analysis, no known vulns), and add the resulting badge id.

## Ceilings we accept (honest, not worth gaming)

- **Code-Review** — Scorecard wants approved changesets; a solo maintainer can't
  approve their own PRs. Stays low until there's a second reviewer/bot.
- **Maintained** — 0 while the repo is < 90 days old; rises automatically with
  sustained commit/issue activity.
- **Contributors** — wants contributors from ≥ 2 organizations; organic.
- **Signed-Releases** — a pure-source npm package has no release *assets* to
  sign (npm provenance is already emitted via OIDC at publish).

## Portable files (copy to another repo)

`.github/workflows/{ci,codeql,scorecard,cflite}.yml` · `.github/dependabot.yml` ·
`.clusterfuzzlite/` · `fuzz/` (adapt the targets to that repo's parsers) ·
`SECURITY.md` · this file. Then re-pin any Action SHAs and do the two operator
actions above.
