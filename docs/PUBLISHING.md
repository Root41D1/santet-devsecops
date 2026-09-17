# Publishing Santet DevSecOps

This checklist prepares the project for its first public GitHub release.

## Recommended repository metadata

- Repository name: `santet-devsecops`
- Visibility: Public
- License: Apache-2.0
- Default branch: `main`
- Description: `Free, open-source DevSecOps automation for source code, containers, Kubernetes manifests, attack paths, SBOMs, and runtime security.`
- Topics: `devsecops`, `security`, `kubernetes`, `kubearmor`, `kubehound`,
  `kube-linter`, `trivy`, `semgrep`, `gitleaks`, `sbom`, `supply-chain-security`

## Pre-publish checklist

1. Confirm the GitHub owner is `Root41D1`.
2. Confirm public URLs use `Root41D1` and GHCR paths use lowercase `root41d1`.
3. Review the project name, description, license, and security contact.
4. Confirm generated `artifacts/` and cluster dumps are not staged.
5. Run the release validation:

   ```bash
   make doctor
   make cluster-doctor
   make scan
   make kubearmor-render
   git diff --check
   git status --short
   ```

6. Review all changed files before committing:

   ```bash
   git diff
   git add -A
   git diff --cached --check
   git diff --cached --stat
   git commit -m "Release Santet DevSecOps v0.1.0"
   ```

## Create and push with GitHub CLI

Authenticate interactively, then create the public repository:

```bash
gh auth login
gh repo create Root41D1/santet-devsecops \
  --public \
  --source=. \
  --remote=origin \
  --description "Free, open-source DevSecOps automation for source code, containers, Kubernetes manifests, attack paths, SBOMs, and runtime security." \
  --push
```

Add the recommended topics:

```bash
gh repo edit Root41D1/santet-devsecops \
  --add-topic devsecops,security,kubernetes,kubearmor,kubehound,kube-linter,trivy,semgrep,gitleaks,sbom,supply-chain-security
```

If the repository already exists, configure it and push explicitly:

```bash
git remote add origin https://github.com/Root41D1/santet-devsecops.git
git push -u origin main
```

## GitHub settings after the first push

1. Enable private vulnerability reporting and secret scanning where available.
2. Protect `main` and require pull requests.
3. Require the `Santet DevSecOps / baseline` status check.
4. Require conversation resolution and prevent force pushes.
5. Enable Dependabot security and version updates.
6. Review the first workflow run and its SARIF uploads.
7. Create release `v0.1.0` from the reviewed commit and paste the matching
   section from `CHANGELOG.md` into the release notes.
8. Confirm the tag workflow publishes `linux/amd64` and `linux/arm64` images,
   SBOM, and provenance to `ghcr.io/root41d1/santet-devsecops`.
9. Change the GHCR package visibility to public and test an unauthenticated
   pull of the immutable `0.1.0` tag before advertising `latest`.

Never add kubeconfig, cluster credentials, KubeHound dumps, or raw production
evidence to the repository or GitHub Actions secrets used by pull requests.
