# Polaris CLI

Connect your codebase to the [Polaris](https://dev.relynce.ai) reliability risk platform. Scan for risks, get control guidance, and manage your reliability posture — all from the terminal or Claude Code.

## Install

**From source (requires Go 1.25+):**

```bash
go install github.com/relynce/polaris-cli/cmd/polaris@latest
```

**From release binary:**

Download from [Releases](https://github.com/relynce/polaris-cli/releases) for your platform.

## Quick Start

```bash
# Configure your API credentials
polaris login

# Initialize a project (installs Claude Code plugin if available)
polaris init

# Check connection and plugin status
polaris status
```

## Claude Code Integration

After `polaris init` (or `polaris plugin install claude`), the following slash commands are available in Claude Code. The core workflow chains automatically: detect → analyze → remediate.

**Multi-Agent Workflow:**

| Command | Description |
|---------|-------------|
| `/polaris:detect-risks` | Multi-agent scan with expert agents, auto-chains to analyze |
| `/polaris:analyze-risks` | Correlate with incidents, enrich with knowledge, score risks (auto-invoked) |
| `/polaris:remediate-risks R-XXX` | Generate plan, apply fixes, submit evidence, resolve risk |

**Guidance and Research:**

| Command | Description |
|---------|-------------|
| `/polaris:risk-guidance R-XXX` | Codebase-specific remediation guidance for a risk |
| `/polaris:risk-check` | Quick read-only check of existing risks |
| `/polaris:control-guidance RC-XXX` | Implementation guidance for a control |
| `/polaris:incident-patterns` | Search historical incident patterns |
| `/polaris:sre-context` | Load full reliability context |

**Review and Evidence:**

| Command | Description |
|---------|-------------|
| `/polaris:reliability-review` | Review code changes for reliability |
| `/polaris:submit-evidence` | Submit control implementation evidence |
| `/polaris:list-open` | List unresolved risks |

## Commands

| Command | Description |
|---------|-------------|
| `polaris login` | Configure API credentials |
| `polaris logout` | Remove stored credentials |
| `polaris init` | Initialize project and install Claude Code plugin |
| `polaris status` | Check connection and plugin status |
| `polaris plugin` | Manage editor plugins (install, update, list, remove) |
| `polaris scan` | Submit risk scan findings |
| `polaris risk` | Manage risks (list, show, close, resolve) |
| `polaris control` | Query the 56-control reliability catalog |
| `polaris knowledge` | Search organizational knowledge base |
| `polaris evidence` | Submit and manage control evidence |
| `polaris config` | Manage configuration |
| `polaris version` | Show version info |

## Configuration

Credentials are stored in `~/.polaris/config.yaml` (mode 0600). The CLI never exposes credentials to LLM contexts.

## License

[Business Source License 1.1](LICENSE) — see LICENSE for details.
