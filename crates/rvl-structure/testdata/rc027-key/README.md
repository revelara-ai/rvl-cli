# RC-027 answer key

`key.jsonl` labels 133 public GitHub repositories, each at a pinned commit,
with the RC-027 (error reporting) verdict a correct repo-structure lane would
give. `examples/rc027_key.rs` scores the lane against it:

    crates/rvl-structure/testdata/rc027-key/fetch.sh /tmp/rc027
    cargo run --release -p rvl-structure --example rc027_key -- \
        crates/rvl-structure/testdata/rc027-key/key.jsonl /tmp/rc027

`fetch.sh` checks out each repository one commit deep (about 9 GB in all).
The example refuses to score a checkout that is not at its key commit.

## Rows

    {"repo": "owner/name", "commit": "<sha>", "kind": "service", "truth": "violates", "why": "..."}

- `kind`: `service` (the repository holds a deployable server program of
  its own, a SaaS backend or a self-hosted server product; a demo or starter
  app counts), `library` (a package other code imports; a framework's own
  `listen` helper does not make it a service), `cli` (run by hand or in CI),
  or `tool` (a daemon beside someone else's service: a sidecar, an exporter,
  a replication agent).
- `truth`:
  - `violates`: a service where nothing in non-test code, manifests or
    deploy config could carry its errors off the host. Any one of these
    rules it out: an error-tracker SDK of any vendor or age (Sentry with
    raven, Bugsnag, Rollbar, Honeybadger, Airbrake, Raygun), even behind a
    setting; an APM agent that captures errors (New Relic, Datadog, Elastic
    APM, Application Insights, Cloud Error Reporting); an OpenTelemetry,
    OpenCensus, Jaeger or Zipkin exporter wired into the server (a Go
    `// indirect` requirement alone does not count); a log shipper or a
    remote log sink (fluent-bit, fluentd, vector, promtail, an otel
    collector, GELF, remote syslog, a log webhook). Logging to stdout and
    exposing Prometheus metrics is a violation.
  - `satisfies`: a service whose code initialises an error tracker and
    whose tree commits alert rules for it.
  - `abstain`: everything else, including a service with some reporting and
    no committed alert rules.
- `why`: the files the label rests on.

The candidates were chosen to cover services without a tracker, services
with a tracker (with and without alert rules), and libraries, frameworks
and CLIs whose sources mention a server. Each row was labelled from its
checkout, blind to the lane's verdict, and every row the lane decides was
fact-checked a second time by hand. The two passes agree on all of them.

## Result at the key's commits

| lane \ key | abstain | violates | satisfies |
|---|---|---|---|
| abstain   | 80 | 31 | 1 |
| violates  | 12 |  9 | 0 |
| satisfies |  0 |  0 | 0 |

- `violates`: precision 9/21 = 0.43, Wilson 95% lower bound 0.25. Below
  the 0.90 serving gate.
  - 7 of the 12 wrong verdicts are not services. The listener the lane
    matched sits in a doc comment or docstring of a framework (express,
    koa, echo, flask), in a string literal (nest), in a CLI (json-server)
    or in a replication tool's metrics endpoint (litestream).
  - 5 are services that do report their errors through a mechanism the
    lane does not search: New Relic (GSA and cds-snc notifications-api),
    OpenTelemetry exporters (open-webui, thanos) and the raven-go Sentry
    SDK (syncthing's crash receiver).
- `satisfies`: no verdicts, so precision is not measured. Public
  repositories rarely commit alert rules beside the service. The one
  service labelled `satisfies` renders its alert rules from a Helm chart
  dependency, which the lane does not read.
- The lane misses 31 of the 40 labelled violations. In 26 it finds no
  listener: the server starts through a call it does not read (gin's
  `Run`, a `cmd` package outside `package main`, Django under gunicorn with
  no `gunicorn*.py`). In the other 5 (unleash, docmost, ollama, wiki.js,
  photoprism) it finds one, but the substring `rollbar` matches
  `scrollbar` in front-end code, which reads as a tracker SDK.
