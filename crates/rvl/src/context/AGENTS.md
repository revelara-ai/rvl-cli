## Revelara

This project uses Revelara for reliability risk analysis. When making design
or implementation decisions that affect reliability (error handling, retries,
timeouts, deployments, data integrity, observability), consult the Revelara
context below and ground the decision in real risk and incident data.

### Context Tools (rvl CLI)

Add `--format=json` to any of these for machine-readable output.

**Risks:**
- `rvl risk list --service=<service>` — current risks for a service
- `rvl risk show R-XXX` — full risk details with mapped controls
- `rvl risk context R-XXX --format=json` — risk + controls + knowledge + incidents
- `rvl risk ready --service=<service>` — risks ready to remediate (no blockers)

**Controls:**
- `rvl control list --limit=100` — reliability controls catalog
- `rvl control show RC-XXX` — control details and evidence status

**Knowledge:**
- `rvl knowledge search "<query>" --limit=5` — search incidents and patterns
- `rvl knowledge enrich --query="<query>"` — enriched context with patterns and procedures

**Evidence & Resolution:**
- `rvl evidence submit --control=RC-XXX --type=code --name="..." --url="..." --description="..."` — record implementation evidence
- `rvl risk resolve R-XXX --reason="..."` — mark a risk as resolved

### Skills

Where your coding agent supports skills or slash commands, the following are
available after `rvl plugin install`:

- `/rvl:scan` — scan the codebase for reliability risks
- `/rvl:fix R-XXX` — guided remediation for a specific risk
- `/rvl:ask "question"` — ask a reliability question to a domain expert
- `/rvl:risks` — view risk posture, open risks, and ready-to-fix items
- `/rvl:review` — review code changes for reliability issues
- `/rvl:evidence RC-XXX` — submit evidence after implementing a control
- `/rvl:status` — check connection and configuration

Agents without slash commands auto-discover the same skills; ask naturally,
e.g. "scan this codebase for reliability risks".
