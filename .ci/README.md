# .ci — relocated GitHub workflow

`github-ci-workflow.yml` is the repository's CI workflow, moved here
from `.github/workflows/ci.yml` **only because the operator's token is
a fine-grained PAT, which has no `workflow` scope and therefore cannot
push files under `.github/workflows/`** (GitHub rejects with
"…without workflow scope"). File content is unchanged.

Restore (any of):
1. GitHub web UI: create `.github/workflows/ci.yml` and paste the file.
2. `git mv .ci/github-ci-workflow.yml .github/workflows/ci.yml` + push
   with a **classic** PAT that has the `workflow` scope checked.

The file is identical (0-line diff) to what was originally in
`.github/workflows/ci.yml` on this branch.
