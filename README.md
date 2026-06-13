
# 🛡️ K8s Security Linter

[![CI](https://github.com/DevSpecOps/k8s-security-linter/actions/workflows/ci.yaml/badge.svg)](https://github.com/DevSpecOps/k8s-security-linter/actions/workflows/ci.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/DevSpecOps/k8s-security-linter)](https://goreportcard.com/report/github.com/DevSpecOps/k8s-security-linter)
[![GitHub release](https://img.shields.io/github/v/release/DevSpecOps/k8s-security-linter)](https://github.com/DevSpecOps/k8s-security-linter/releases)
[![License](https://img.shields.io/github/license/DevSpecOps/k8s-security-linter)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue)](https://github.com/DevSpecOps/k8s-security-linter/pkgs/container/k8s-security-linter)

**Static analysis tool for Kubernetes YAML manifests** – detects security misconfigurations (privileged containers, root user, missing memory limits, latest image tags, etc.) using **OPA/Rego**.

## ✨ Features

- 🔍 5 built‑in security rules (easily extensible via Rego)
- 🐳 Works with Pod, Deployment, StatefulSet, DaemonSet, Job, CronJob
- 📊 JSON output for CI integration
- ✅ Exit code 1 on violation – fails CI pipelines
- 🧩 Rego policy engine – add custom rules without recompiling
- 🐳 Docker image available

## 🚀 Quick start

### Local binary

```bash
git clone https://github.com/DevSpecOps/k8s-security-linter.git
cd k8s-security-linter
go build -o k8s-security-linter ./cmd/k8s-security-linter
./k8s-security-linter --path ./test/fixtures/bad
```

### Docker

```bash
docker run --rm -v $(pwd):/workspace ghcr.io/devspecops/k8s-security-linter --path /workspace
```

### GitHub Action

```yaml
- uses: DevSpecOps/k8s-security-linter@v0.1.4
  with:
    path: './deploy'
    json: 'false'
```

### Pre-commit

Add to `.pre-commit-config.yaml`:

```yaml
- repo: https://github.com/DevSpecOps/k8s-security-linter
  rev: v0.1.4
  hooks:
    - id: k8s-security-linter
```

## 📋 Rules (default)

| Rule ID | Description |
|---------|-------------|
| PRIVILEGED | `privileged: true` not allowed |
| RUN_AS_NON_ROOT | `runAsNonRoot` must be true |
| READONLY_ROOT | `readOnlyRootFilesystem` must be true |
| NO_MEMORY_LIMITS | `resources.limits.memory` required |
| LATEST_TAG | Image tag must not be `latest` or implicit |

## 🧪 Custom rules

Add your own Rego policies by modifying `pkg/engine/rules.rego` – the tool uses embedded policies.

## 🛠 Development

```bash
make test          # run unit tests
make build         # compile binary
make docker        # build Docker image
```

## 📄 License

Apache 2.0

---

**Star** ⭐ if you find it useful!
