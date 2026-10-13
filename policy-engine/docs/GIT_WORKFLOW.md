# Git workflow for Member 5

Do this from the **actual team repository**. The standalone ZIP cannot create a branch in that repository.

```bash
git status
git switch main
git pull --ff-only
git switch -c feature/policy-engine
```

Copy/adapt the `securepam_policy_engine/`, `tests/`, `policies.json`, `pyproject.toml`, and relevant `docs/` into the agreed team-repo locations. Avoid overwriting existing shared files without review.

```bash
python -m pip install -e ".[test]"
python -m pytest
git status
git add securepam_policy_engine tests policies.json pyproject.toml docs
git commit -m "feat: add centralized SecurePAM policy evaluator"
git push -u origin feature/policy-engine
```

Open a Pull Request into `main`, summarize policy precedence and integration assumptions, attach test results, and request review from the project lead/backend owner. Do not push directly to protected `main`. If the team uses a different branch name or monorepo layout, follow that convention.
