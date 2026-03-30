# Contributing

## Fork Workflow

This fork intentionally uses two lanes:

- `main` is the fork integration branch.
  It may contain changes needed by downstream consumers such as `isol8`.
- `feat/*` branches are short-lived proof branches.
  They should only merge into `main` after they are validated in a real downstream integration path.

## Upstream Tracking

- Keep `upstream/main` as the reference branch for `edera-dev/styrolite`.
- Periodically merge or rebase `upstream/main` into this fork's `main` when upstream moves.
- Do not stack experimental work directly on top of stale feature branches.

Recommended update flow:

1. `git fetch upstream origin`
2. `git checkout main`
3. `git merge upstream/main`
4. Resolve conflicts and re-run local validation
5. Push `main` back to `origin`

## Upstream Pull Requests

Do not open upstream pull requests directly from this fork's `main`.

Instead:

1. Start from `upstream/main`
2. Cherry-pick or reimplement the smallest generic change set
3. Open one focused PR per logical fix

Examples of upstream-friendly slices:

- generic attach/runtime correctness
- capability handling fixes
- mount API improvements
- explicit resource-limit semantics

Keep downstream-only integration details out of upstream PRs.

## Validation Expectation

Before merging `feat/*` into `main`, validate the branch in the real downstream consumer that motivated the change. For the current fork, that usually means validating through `isol8`, not only by running `styrolite` unit tests in isolation.
