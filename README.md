# Revelara CLI

Connect your codebase to the [Revelara](https://dev.revelara.ai) reliability risk platform. Scan for risks, get control guidance, and manage your reliability posture — all from the terminal or Claude Code.

## Install

**From source (requires Go 1.25+):**

```bash
go install github.com/relynce/rely-cli/cmd/rvl@latest
```

**From release binary:**

Download from [Releases](https://github.com/relynce/rely-cli/releases) for your platform.

## Quick Start

```bash
# Configure your API credentials
rvl login

# Initialize a project (installs Claude Code plugin if available)
rvl init

# Check connection and plugin status
rvl status
```

## Claude Code Integration

After `rvl init` (or `rvl plugin install claude`), the following slash commands are available in Claude Code. The core workflow chains automatically: detect → analyze → remediate.

**Multi-Agent Workflow:**

| Command | Description |
|---------|-------------|
| `/rvl:detect-risks` | Multi-agent scan with expert agents, auto-chains to analyze |
| `/rvl:analyze-risks` | Correlate with incidents, enrich with knowledge, score risks (auto-invoked) |
| `/rvl:remediate-risks R-XXX` | Generate plan, apply fixes, submit evidence, resolve risk |

**Guidance and Research:**

| Command | Description |
|---------|-------------|
| `/rvl:risk-guidance R-XXX` | Codebase-specific remediation guidance for a risk |
| `/rvl:risk-check` | Quick read-only check of existing risks |
| `/rvl:control-guidance RC-XXX` | Implementation guidance for a control |
| `/rvl:incident-patterns` | Search historical incident patterns |
| `/rvl:sre-context` | Load full reliability context |

**Review and Evidence:**

| Command | Description |
|---------|-------------|
| `/rvl:reliability-review` | Review code changes for reliability |
| `/rvl:submit-evidence` | Submit control implementation evidence |
| `/rvl:list-open` | List unresolved risks |

## Commands

| Command | Description |
|---------|-------------|
| `rvl login` | Configure API credentials |
| `rvl logout` | Remove stored credentials |
| `rvl init` | Initialize project and install Claude Code plugin |
| `rvl status` | Check connection and plugin status |
| `rvl plugin` | Manage editor plugins (install, update, list, remove) |
| `rvl scan` | Submit risk scan findings |
| `rvl risk` | Manage risks (list, show, close, resolve) |
| `rvl control` | Query the 56-control reliability catalog |
| `rvl knowledge` | Search organizational knowledge base |
| `rvl evidence` | Submit and manage control evidence |
| `rvl config` | Manage configuration |
| `rvl version` | Show version info |

## Configuration

Credentials are stored in `~/.revelara/config.yaml` (mode 0600). The CLI never exposes credentials to LLM contexts.

## License

[Business Source License 1.1](LICENSE) — see LICENSE for details.
