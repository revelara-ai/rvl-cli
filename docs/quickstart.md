# Revelara Quickstart Guide

## Welcome to Revelara

Revelara is a reliability risk analysis platform that works in your browser and your IDE. Whether you're a developer, SRE, or engineering leader, Revelara gives you the insights you need to build more resilient systems.

## Accepting Your Invite and First Login

Revelara is currently invite-only. You'll receive an email invitation with a link to get started.

1. **Click the link** in your invitation email
2. **Create your account** — sign up with Google, GitHub, Microsoft, or email and password
3. **Verify your email** — check your inbox and click the verification link
4. **You're in.** You'll be directed to the main interface

## Your First Look Around

Revelara has five main sections accessible from the top navigation:

**Analysis** — Chat-based incident exploration. Ask questions about your organization's historical incidents and get AI-powered answers with sources cited.

**Documents** — Browse, search, and upload incident reports, postmortems, and RCAs. Upload your team's postmortems here to build shared learning.

**Knowledge** — Curated facts, procedures, and failure patterns extracted from incident analysis. Think of this as your team's reliability playbook.

**Risks** — Your risk register dashboard. See your team's current reliability posture, browse detected risks, and track compliance.

**Timeline** — Visual incident timelines. Explore patterns across years of incidents.

If you belong to multiple organizations, use the organization switcher in the header to switch between them.

## Setting Up Claude Code Integration

The Claude Code integration is how you scan your codebase for reliability risks. These scan results feed into the risk register, map to compliance controls, and populate the dashboards you see in the web UI. To get the most out of Revelara, you'll want to set this up.

### Prerequisites

- Claude Code installed and working on your machine
- A Revelara API key (create one below before installing the CLI)

### Step 1: Create an API Key

You'll need an API key to connect the CLI to your Revelara account.

1. Log in to Revelara at [dev.revelara.ai](https://dev.revelara.ai)
2. Click your profile picture in the top-right corner
3. Go to **API Keys**
4. Click **Create New Key**
5. Give your key a name (e.g., "My Laptop")
6. Click **Create**
7. **Copy your key immediately** — it's only shown once. If you lose it, delete and create a new one.

### Step 2: Install the CLI

Install the Revelara command-line tool:

```bash
go install github.com/relynce/rely-cli/cmd/rvl@latest
```

Or download a pre-built binary from the [releases page](https://github.com/relynce/rely-cli/releases).

### Step 3: Configure the CLI

Run the interactive setup — you'll need the API key you copied in Step 1:

```bash
rvl login
```

You'll be prompted for your API URL, API Key, and Organization name.

### Step 4: Verify Your Setup

```bash
rvl status
```

You should see a message confirming your connection.

### Step 5: Initialize Your Project

From within your project's git repository, run:

```bash
rvl init
```

This creates a `.revelara.yaml` project configuration file and installs the Revelara skills for Claude Code.

You can also run non-interactively:

```bash
rvl init --project my-service -y
```

#### Understanding `.revelara.yaml`

The `.revelara.yaml` file identifies your project:

```yaml
project: my-service
components:
  - name: api
    path: cmd/api/
  - name: worker
    path: cmd/worker/
```

- **`project`** — The service name used in the risk register. All risks detected in this repo are filed under this name.
- **`components`** — Optional list of sub-components for finer-grained visibility.

## Core Workflow: Detect, Understand, Resolve

### Detect: Find Risks in Your Code

Scan your codebase to identify potential reliability issues:

```
/rvl:detect-risks
```

This runs a full scan and saves findings to the risk register. The service name is auto-detected from your `.revelara.yaml`.

You can also scan a different project from your current session:

```
/rvl:detect-risks /path/to/other-project
```

For a quick read-only assessment without saving results:

```
/rvl:risk-check my-service
```

### Understand: Learn What the Risk Means

Get context on detected risks and learn how to fix them:

```
/rvl:control-guidance RC-015
```

Search historical incidents for patterns related to your risk:

```
/rvl:incident-patterns "database failover"
```

Load reliability context for your entire session:

```
/rvl:sre-context
```

Or visit the **Risks** tab in the web UI to browse the full risk register and see recommended actions.

### Resolve: Fix the Risk and Record It

1. Implement the fix recommended in the control guidance
2. Submit evidence that you've addressed the control:
   ```
   /rvl:submit-evidence RC-015
   ```
3. Review your changes for remaining reliability issues:
   ```
   /rvl:reliability-review
   ```

## Quick Reference: All Skills

| Skill | Description |
|-------|-------------|
| `/rvl:detect-risks [service or path]` | Full codebase scan, saves risks to the register |
| `/rvl:risk-check <service>` | Quick assessment without saving results |
| `/rvl:control-guidance RC-XXX` | Implementation guidance for a specific control |
| `/rvl:reliability-review` | Analyze your git diff for reliability issues |
| `/rvl:incident-patterns <query>` | Search historical incidents for patterns |
| `/rvl:sre-context` | Load full reliability context for your session |
| `/rvl:submit-evidence RC-XXX` | Record that you've implemented a control |
| `/rvl:list-open` | List open risks assigned to you |

## Troubleshooting

**"Not configured" error**

Run `rvl login` to set up your CLI credentials.

**"Connection failed" error**

Check that the Revelara server is reachable. Verify your API URL is correct with `rvl status`.

**"Invalid or expired API key" error**

Create a new API key in Settings -> API Keys. Your previous key is no longer valid.

**"Insufficient permissions" error**

Your API key may not have the required permissions. Delete the old key and create a new one.

**Skills don't show up in Claude Code**

Run `rvl init` to install skills. If you've already run init, try `rvl init --force` to reinstall. Restart Claude Code if needed.

## Next Steps

1. **Run Your First Scan** — Run `/rvl:detect-risks` on one of your team's services. This populates the risk register and compliance dashboards.

2. **Upload Your Postmortems** — Go to Documents and upload your team's incident reports and RCAs.

3. **Explore the Risk Register** — Visit the Risks tab to see detected risks mapped to compliance controls.

4. **Read the Full User Guide** — For comprehensive coverage of all features, see the [User Guide](user-guide.md).

## Questions?

If you get stuck, check the [Troubleshooting](#troubleshooting) section above or reach out to your Revelara administrator.
