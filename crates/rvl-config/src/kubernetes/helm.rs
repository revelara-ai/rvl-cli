//! Bounded, deterministic helm rendering with COMMITTED values only.
//!
//! A `Chart.yaml` renders the chart's OWN templates against the committed
//! `values.yaml` (plus `.Chart.*` metadata from `Chart.yaml` itself) and
//! stamps the resulting packets `rendered` — trustworthy but one step
//! removed from authored text. No cluster is consulted and nothing is
//! fetched, ever. Vendored subcharts under `charts/` are visited as chart
//! roots of their own by the walk (approximation: parent value overrides
//! are not applied to them).
//!
//! The renderer is a deliberately SMALL template subset, chosen to cover
//! the `helm create` scaffold shape: `if`/`else`/`end` and `with` blocks
//! whose conditions are committed-value truthiness, scalar `.Values` /
//! `.Chart` / `.Release` substitution, the `default`/`quote`/`int`/
//! `toString`/`lower`/`upper`/`trim` pipes, and `toYaml` + `nindent`/
//! `indent` block insertion. `include`/`template`/`printf` calls become a
//! deterministic identity placeholder (`release-<chart>`) — allowed for
//! names and labels, REFUSED on any line that could feed an inventoried
//! value (an image, a resource bound): fabricating those would be a guess.
//! A template using anything outside the subset abstains per-file with a
//! `helm-unrendered-template` sighting; a chart declaring dependencies not
//! vendored in-tree abstains entirely with `helm-unvendored-dependencies`.

use super::manifest::{self, get, Emitter, ProvenanceOracle};
use crate::{render_value, FormatSighting, ProvenanceStep, Resolution, Retrieved};
use serde_yaml::Value;
use std::path::Path;

/// Line keys whose VALUE the G6 inventory reads: a placeholder here would
/// fabricate a fact, so the file abstains instead.
const RESTRICTED_KEYS: &[&str] = &[
    "image",
    "imagePullPolicy",
    "replicas",
    "minReplicas",
    "maxReplicas",
    "minAvailable",
    "maxUnavailable",
    "maxSurge",
    "terminationGracePeriodSeconds",
    "priorityClassName",
    "cpu",
    "memory",
    "kind",
    "apiVersion",
    "type",
];

/// Parent keys whose BLOCK the inventory reads: a placeholder block under
/// one of these would fabricate structured facts.
const RESTRICTED_PARENTS: &[&str] = &[
    "resources",
    "limits",
    "requests",
    "securityContext",
    "livenessProbe",
    "readinessProbe",
    "startupProbe",
    "strategy",
    "rollingUpdate",
];

struct RenderCtx<'a> {
    values: &'a Value,
    chart_name: &'a str,
    app_version: &'a str,
    chart_version: &'a str,
}

/// The single failure mode: some construct outside the bounded subset.
struct Unsupported;

/// An evaluated template expression.
enum Eval {
    /// A committed value (renderable as scalar or via toYaml).
    Val(Value),
    /// The value does not exist in committed inputs (falsy; scalar use is
    /// unsupported unless a `default` pipe supplies one).
    Absent,
    /// An identity placeholder for include/template/printf calls.
    Placeholder,
    /// Multi-line output (toYaml/nindent).
    Block(String),
}

fn truthy(e: &Eval) -> Result<bool, Unsupported> {
    Ok(match e {
        Eval::Absent => false,
        Eval::Placeholder => return Err(Unsupported),
        Eval::Block(_) => return Err(Unsupported),
        Eval::Val(v) => match v {
            Value::Null => false,
            Value::Bool(b) => *b,
            Value::Number(n) => n.as_f64() != Some(0.0),
            Value::String(s) => !s.is_empty(),
            Value::Sequence(s) => !s.is_empty(),
            Value::Mapping(m) => !m.is_empty(),
            Value::Tagged(_) => true,
        },
    })
}

fn scalar(e: &Eval) -> Result<String, Unsupported> {
    match e {
        Eval::Val(Value::Mapping(_)) | Eval::Val(Value::Sequence(_)) => Err(Unsupported),
        Eval::Val(v) => Ok(render_value(v)),
        Eval::Placeholder => Err(Unsupported), // callers decide placeholder policy first
        Eval::Absent | Eval::Block(_) => Err(Unsupported),
    }
}

/// Split on whitespace, keeping double-quoted strings whole.
fn tokenize(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in s.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                cur.push(c);
            }
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn dig_path<'a>(base: &'a Value, dotted: &str) -> Option<&'a Value> {
    let mut cur = base;
    for seg in dotted.split('.').filter(|s| !s.is_empty()) {
        cur = get(cur.as_mapping()?, seg)?;
    }
    Some(cur)
}

fn to_yaml_block(e: Eval) -> Result<Eval, Unsupported> {
    match e {
        Eval::Val(v) => {
            let text = serde_yaml::to_string(&v).map_err(|_| Unsupported)?;
            Ok(Eval::Block(text.trim_end().to_string()))
        }
        _ => Err(Unsupported),
    }
}

/// Evaluate one pipeline segment's base term. `toYaml X` and `default D X`
/// also appear in function form, not just as pipes.
fn eval_term(tokens: &[String], ctx: &RenderCtx, dot: Option<&Value>) -> Result<Eval, Unsupported> {
    let Some(first) = tokens.first() else {
        return Err(Unsupported);
    };
    match first.as_str() {
        "include" | "template" | "printf" | "tpl" => return Ok(Eval::Placeholder),
        "not" => {
            let inner = eval_term(&tokens[1..], ctx, dot)?;
            return Ok(Eval::Val(Value::Bool(!truthy(&inner)?)));
        }
        "toYaml" => return to_yaml_block(eval_term(&tokens[1..], ctx, dot)?),
        "default" if tokens.len() >= 3 => {
            let v = eval_term(&tokens[2..], ctx, dot)?;
            return if truthy(&v).unwrap_or(false) {
                Ok(v)
            } else {
                eval_term(&tokens[1..2], ctx, dot)
            };
        }
        _ => {}
    }
    if tokens.len() != 1 {
        return Err(Unsupported);
    }
    let t = first.as_str();
    if let Some(stripped) = t.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        return Ok(Eval::Val(Value::String(stripped.to_string())));
    }
    if t == "true" || t == "false" {
        return Ok(Eval::Val(Value::Bool(t == "true")));
    }
    if let Ok(n) = t.parse::<i64>() {
        return Ok(Eval::Val(Value::Number(n.into())));
    }
    match t {
        "." => return dot.cloned().map(Eval::Val).ok_or(Unsupported),
        ".Chart.Name" => return Ok(Eval::Val(Value::String(ctx.chart_name.to_string()))),
        ".Chart.AppVersion" => return Ok(Eval::Val(Value::String(ctx.app_version.to_string()))),
        ".Chart.Version" => return Ok(Eval::Val(Value::String(ctx.chart_version.to_string()))),
        ".Release.Name" => return Ok(Eval::Val(Value::String("release".to_string()))),
        ".Release.Namespace" => return Ok(Eval::Val(Value::String("default".to_string()))),
        ".Release.Service" => return Ok(Eval::Val(Value::String("Helm".to_string()))),
        _ => {}
    }
    if let Some(path) = t.strip_prefix(".Values") {
        return Ok(match dig_path(ctx.values, path) {
            Some(v) => Eval::Val(v.clone()),
            None => Eval::Absent,
        });
    }
    if let Some(path) = t.strip_prefix('.') {
        // Relative field under a `with`-bound dot; anything else (.Files,
        // .Capabilities, $vars, function calls) is outside the subset.
        if let Some(dot) = dot {
            return Ok(match dig_path(dot, path) {
                Some(v) => Eval::Val(v.clone()),
                None => Eval::Absent,
            });
        }
    }
    Err(Unsupported)
}

/// Evaluate a full `a | pipe | pipe` expression.
fn eval_expr(expr: &str, ctx: &RenderCtx, dot: Option<&Value>) -> Result<Eval, Unsupported> {
    let mut segments = expr.split('|').map(str::trim);
    let first = segments.next().ok_or(Unsupported)?;
    let mut cur = eval_term(&tokenize(first), ctx, dot)?;
    for seg in segments {
        let tokens = tokenize(seg);
        let Some(name) = tokens.first() else {
            return Err(Unsupported);
        };
        cur = match (name.as_str(), tokens.len()) {
            ("default", 2) => {
                if truthy(&cur).unwrap_or(false) {
                    cur
                } else {
                    eval_term(&tokens[1..], ctx, dot)?
                }
            }
            ("quote", 1) => Eval::Val(Value::String(format!("\"{}\"", scalar(&cur)?))),
            ("squote", 1) => Eval::Val(Value::String(format!("'{}'", scalar(&cur)?))),
            ("int" | "toString" | "trim", 1) => Eval::Val(Value::String(scalar(&cur)?)),
            ("lower", 1) => Eval::Val(Value::String(scalar(&cur)?.to_lowercase())),
            ("upper", 1) => Eval::Val(Value::String(scalar(&cur)?.to_uppercase())),
            ("toYaml", 1) => to_yaml_block(cur)?,
            ("nindent" | "indent", 2) => {
                let n: usize = tokens[1].parse().map_err(|_| Unsupported)?;
                let text = match &cur {
                    Eval::Block(b) => b.clone(),
                    other => scalar(other)?,
                };
                let pad = " ".repeat(n);
                Eval::Block(
                    text.lines()
                        .map(|l| format!("{pad}{l}"))
                        .collect::<Vec<_>>()
                        .join("\n"),
                )
            }
            _ => return Err(Unsupported),
        };
    }
    Ok(cur)
}

/// The key of a `key: ...` line, if it has one.
fn line_key(line: &str) -> Option<&str> {
    let t = line.trim_start().trim_start_matches("- ").trim_start();
    let (key, _) = t.split_once(':')?;
    let key = key.trim();
    (!key.is_empty() && !key.contains(' ') && !key.contains('{')).then_some(key)
}

struct Frame {
    emitting: bool,
    /// Whether some branch of this if-chain already emitted.
    done: bool,
    dot: Option<Value>,
}

/// Strip `{{/* ... */}}` comments; a comment left open on the line is
/// outside the subset.
fn strip_comments(line: &str) -> Result<String, Unsupported> {
    let mut out = line.to_string();
    while let Some(start) = out.find("{{").filter(|&i| {
        let rest = &out[i + 2..];
        rest.trim_start_matches('-').trim_start().starts_with("/*")
    }) {
        let Some(endc) = out[start..].find("*/") else {
            return Err(Unsupported);
        };
        let after = start + endc + 2;
        let Some(close) = out[after..].find("}}") else {
            return Err(Unsupported);
        };
        out.replace_range(start..after + close + 2, "");
    }
    Ok(out)
}

/// Render one template with committed inputs. Any construct outside the
/// bounded subset fails the whole file — abstention, never a guess.
fn render(text: &str, ctx: &RenderCtx) -> Result<String, Unsupported> {
    let mut frames: Vec<Frame> = Vec::new();
    let mut out: Vec<String> = Vec::new();
    let mut last_key: Option<String> = None;

    for raw in text.lines() {
        let line = strip_comments(raw)?;
        let emitting = frames.iter().all(|f| f.emitting);
        let trimmed = line.trim();

        // A lone `{{ ... }}` carrying a control keyword steers the frame
        // stack and emits nothing.
        let control = trimmed
            .strip_prefix("{{")
            .and_then(|s| s.strip_suffix("}}"))
            .map(|s| s.trim_start_matches('-').trim_end_matches('-').trim())
            .filter(|inner| {
                matches!(
                    inner.split_whitespace().next(),
                    Some("if" | "else" | "end" | "with" | "range" | "define" | "block")
                )
            });
        if let Some(inner) = control {
            let dot_frame = frames.iter().rev().find_map(|f| f.dot.clone());
            let mut words = inner.split_whitespace();
            match words.next() {
                Some("if") => {
                    let cond = emitting
                        && truthy(&eval_expr(
                            inner.trim_start_matches("if").trim(),
                            ctx,
                            dot_frame.as_ref(),
                        )?)?;
                    frames.push(Frame {
                        emitting: cond,
                        done: cond,
                        dot: None,
                    });
                }
                Some("else") => {
                    let rest = inner.trim_start_matches("else").trim();
                    if frames.is_empty() {
                        return Err(Unsupported);
                    }
                    let parent_emitting = {
                        let n = frames.len();
                        frames[..n - 1].iter().all(|f| f.emitting)
                    };
                    let top = frames.last_mut().expect("checked above");
                    let branch = if rest.is_empty() {
                        parent_emitting && !top.done
                    } else if let Some(cond_expr) = rest.strip_prefix("if ") {
                        let want = parent_emitting && !top.done;
                        want && truthy(&eval_expr(cond_expr.trim(), ctx, dot_frame.as_ref())?)?
                    } else {
                        return Err(Unsupported);
                    };
                    top.emitting = branch;
                    top.done |= branch;
                }
                Some("end") => {
                    frames.pop().ok_or(Unsupported)?;
                }
                Some("with") => {
                    let expr = inner.trim_start_matches("with").trim();
                    if emitting {
                        let v = eval_expr(expr, ctx, dot_frame.as_ref())?;
                        let on = truthy(&v)?;
                        let dot = match (on, v) {
                            (true, Eval::Val(val)) => Some(val),
                            _ => None,
                        };
                        frames.push(Frame {
                            emitting: on,
                            done: on,
                            dot,
                        });
                    } else {
                        frames.push(Frame {
                            emitting: false,
                            done: false,
                            dot: None,
                        });
                    }
                }
                Some("range" | "define" | "block") => {
                    if emitting {
                        return Err(Unsupported);
                    }
                    // Dead branch: push a dead frame so its `end` balances.
                    frames.push(Frame {
                        emitting: false,
                        done: false,
                        dot: None,
                    });
                }
                _ => return Err(Unsupported),
            }
            continue;
        }

        if !emitting {
            continue;
        }
        if !line.contains("{{") {
            if let Some(k) = line_key(&line) {
                last_key = Some(k.to_string());
            }
            out.push(line);
            continue;
        }

        // Substitute inline expressions. A line that IS one expression may
        // yield a block; embedded expressions must yield scalars.
        let dot_frame = frames.iter().rev().find_map(|f| f.dot.clone());
        let key = line_key(&line).map(str::to_string);
        let whole = trimmed
            .strip_prefix("{{")
            .and_then(|s| s.strip_suffix("}}"))
            .map(|s| s.trim_start_matches('-').trim_end_matches('-').trim());
        if let Some(expr) = whole {
            let v = eval_expr(expr, ctx, dot_frame.as_ref())?;
            match v {
                Eval::Block(b) => {
                    // A placeholder can hide inside a block only via pipes
                    // over Placeholder, which scalar() already refuses.
                    if last_key
                        .as_deref()
                        .is_some_and(|k| RESTRICTED_PARENTS.contains(&k))
                        && expr.contains("include")
                    {
                        return Err(Unsupported);
                    }
                    out.push(b);
                }
                Eval::Placeholder => {
                    if last_key
                        .as_deref()
                        .is_some_and(|k| RESTRICTED_PARENTS.contains(&k))
                    {
                        return Err(Unsupported);
                    }
                    out.push(format!("release-{}", ctx.chart_name));
                }
                other => out.push(scalar(&other)?),
            }
            continue;
        }

        let mut rest = line.clone();
        let mut rendered = String::new();
        while let Some(start) = rest.find("{{") {
            let Some(close) = rest[start..].find("}}") else {
                return Err(Unsupported);
            };
            rendered.push_str(&rest[..start]);
            let expr = rest[start + 2..start + close]
                .trim_start_matches('-')
                .trim_end_matches('-')
                .trim()
                .to_string();
            let after = start + close + 2;
            rest = rest[after..].to_string();
            let v = eval_expr(&expr, ctx, dot_frame.as_ref())?;
            match v {
                Eval::Placeholder => {
                    // An identity placeholder must never feed a value the
                    // inventory reads.
                    if key.as_deref().is_some_and(|k| RESTRICTED_KEYS.contains(&k)) {
                        return Err(Unsupported);
                    }
                    rendered.push_str(&format!("release-{}", ctx.chart_name));
                }
                other => rendered.push_str(&scalar(&other)?),
            }
        }
        rendered.push_str(&rest);
        if let Some(k) = line_key(&rendered) {
            last_key = Some(k.to_string());
        }
        out.push(rendered);
    }

    if !frames.is_empty() {
        return Err(Unsupported);
    }
    Ok(out.join("\n"))
}

/// The render oracle: values came through the template from committed
/// inputs; absences resolve documented defaults like any manifest.
struct HelmOracle<'a> {
    template: &'a str,
    values: &'a str,
}

impl ProvenanceOracle for HelmOracle<'_> {
    fn present(&self, _lookup_path: &str, display_path: &str) -> (Resolution, Vec<ProvenanceStep>) {
        (
            Resolution::Rendered,
            vec![
                ProvenanceStep::new(self.template, display_path, "rendered"),
                ProvenanceStep::new(self.values, "values", "render-input"),
            ],
        )
    }
    fn absent(&self, display_path: &str, platform_key: &str) -> Vec<ProvenanceStep> {
        vec![
            ProvenanceStep::new(self.template, display_path, "absent"),
            ProvenanceStep::new("", platform_key, "platform-default"),
        ]
    }
}

fn parent_dir(rel_path: &str) -> &str {
    rel_path.rsplit_once('/').map(|(d, _)| d).unwrap_or("")
}

/// Collect the chart's own template files (never `charts/`), sorted for
/// deterministic output; partials (`_*.tpl`) and NOTES are not manifests.
fn template_files(root: &Path, chart_dir: &str) -> Vec<String> {
    let mut out = Vec::new();
    let base = if chart_dir.is_empty() {
        "templates".to_string()
    } else {
        format!("{chart_dir}/templates")
    };
    let mut stack = vec![base];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(root.join(&dir)) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let rel = format!("{dir}/{name}");
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                stack.push(rel);
            } else if (name.ends_with(".yaml") || name.ends_with(".yml")) && !name.starts_with('_')
            {
                out.push(rel);
            }
        }
    }
    out.sort();
    out
}

/// Render a chart's own templates with its committed values.
pub(crate) fn retrieve(
    root: &Path,
    rel_path: &str,
    contents: &str,
    snapshot_id: &str,
) -> Retrieved {
    let mut out = Retrieved::default();
    let chart = match serde_yaml::from_str::<Value>(contents) {
        Ok(v @ Value::Mapping(_)) => v,
        _ => {
            out.unparseable = 1;
            return out;
        }
    };
    let chart_dir = parent_dir(rel_path);
    let dir_name = chart_dir.rsplit('/').next().unwrap_or(chart_dir);
    let chart_map = chart.as_mapping().expect("checked above");
    let chart_name = get(chart_map, "name")
        .and_then(Value::as_str)
        .unwrap_or(dir_name)
        .to_string();
    let app_version = get(chart_map, "appVersion")
        .map(render_value)
        .unwrap_or_default();
    let chart_version = get(chart_map, "version")
        .map(render_value)
        .unwrap_or_default();

    // Dependencies must be vendored in-tree (a directory or packed .tgz
    // under charts/); otherwise rendering would need a fetch — abstain.
    let deps: Vec<&str> = get(chart_map, "dependencies")
        .and_then(Value::as_sequence)
        .into_iter()
        .flatten()
        .filter_map(Value::as_mapping)
        .filter_map(|d| get(d, "name").and_then(Value::as_str))
        .collect();
    let charts_dir = if chart_dir.is_empty() {
        "charts".to_string()
    } else {
        format!("{chart_dir}/charts")
    };
    let vendored = |dep: &str| {
        if root.join(&charts_dir).join(dep).is_dir() {
            return true;
        }
        std::fs::read_dir(root.join(&charts_dir))
            .map(|entries| {
                entries.flatten().any(|e| {
                    let n = e.file_name().to_string_lossy().into_owned();
                    n.starts_with(&format!("{dep}-")) && n.ends_with(".tgz")
                })
            })
            .unwrap_or(false)
    };
    if deps.iter().any(|d| !vendored(d)) {
        out.sightings.push(FormatSighting {
            format: "helm-unvendored-dependencies".to_string(),
            file_count: 1,
        });
        return out;
    }

    // Committed values only; a missing values.yaml renders against nothing.
    let mut values = Value::Null;
    let mut values_rel = String::new();
    for name in ["values.yaml", "values.yml"] {
        let rel = if chart_dir.is_empty() {
            name.to_string()
        } else {
            format!("{chart_dir}/{name}")
        };
        if let Ok(text) = std::fs::read_to_string(root.join(&rel)) {
            match serde_yaml::from_str::<Value>(&text) {
                Ok(v) => {
                    values = v;
                    values_rel = rel;
                }
                Err(_) => out.unparseable += 1,
            }
            break;
        }
    }
    let ctx = RenderCtx {
        values: &values,
        chart_name: &chart_name,
        app_version: &app_version,
        chart_version: &chart_version,
    };

    let mut unrendered = 0usize;
    for template_rel in template_files(root, chart_dir) {
        let Ok(text) = std::fs::read_to_string(root.join(&template_rel)) else {
            out.unparseable += 1;
            continue;
        };
        let Ok(rendered) = render(&text, &ctx) else {
            unrendered += 1;
            continue;
        };
        let (docs, failed) = manifest::parse_docs(&rendered);
        if failed {
            out.unparseable += 1;
        }
        let oracle = HelmOracle {
            template: &template_rel,
            values: &values_rel,
        };
        let mut em = Emitter {
            file_anchor: &template_rel,
            snapshot_id,
            oracle: &oracle,
            out: Vec::new(),
        };
        for doc in &docs {
            manifest::packets_from_doc(doc, &mut em);
        }
        out.packets.extend(em.out);
    }
    if unrendered > 0 {
        out.sightings.push(FormatSighting {
            format: "helm-unrendered-template".to_string(),
            file_count: unrendered,
        });
    }
    out
}

/// Whether this file sits under `<chart>/templates/` for some ancestor chart
/// root (in which case the Chart.yaml visit owns it).
pub(crate) fn under_chart_templates(root: &Path, rel_path: &str) -> bool {
    let mut prefix = String::new();
    for seg in rel_path.split('/') {
        if seg == "templates" {
            let chart_yaml = if prefix.is_empty() {
                "Chart.yaml".to_string()
            } else {
                format!("{prefix}/Chart.yaml")
            };
            let chart_yml = chart_yaml.replace("Chart.yaml", "Chart.yml");
            if root.join(&chart_yaml).is_file() || root.join(&chart_yml).is_file() {
                return true;
            }
        }
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(seg);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConfigPacket, Resolution};
    use std::path::Path;

    const CHART: &str = "\
apiVersion: v2
name: mychart
version: 0.1.0
appVersion: \"1.16.0\"
";

    const VALUES: &str = "\
replicaCount: 2
image:
  repository: example/web
  tag: \"\"
autoscaling:
  enabled: false
  minReplicas: 1
  maxReplicas: 5
resources:
  limits:
    cpu: 200m
    memory: 128Mi
livenessProbe:
  httpGet:
    path: /healthz
    port: http
";

    const DEPLOYMENT_TPL: &str = "\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include \"mychart.fullname\" . }}
  labels:
    app: {{ .Chart.Name }}
spec:
  {{- if not .Values.autoscaling.enabled }}
  replicas: {{ .Values.replicaCount }}
  {{- end }}
  template:
    spec:
      containers:
        - name: {{ .Chart.Name }}
          image: \"{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}\"
          {{- with .Values.livenessProbe }}
          livenessProbe:
            {{- toYaml . | nindent 12 }}
          {{- end }}
          resources:
            {{- toYaml .Values.resources | nindent 12 }}
";

    const HPA_TPL: &str = "\
{{- if .Values.autoscaling.enabled }}
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: web
spec:
  minReplicas: {{ .Values.autoscaling.minReplicas }}
  maxReplicas: {{ .Values.autoscaling.maxReplicas }}
{{- end }}
";

    fn write(root: &Path, rel: &str, contents: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, contents).unwrap();
    }

    fn chart_fixture(root: &Path) {
        write(root, "chart/Chart.yaml", CHART);
        write(root, "chart/values.yaml", VALUES);
        write(root, "chart/templates/deployment.yaml", DEPLOYMENT_TPL);
        write(root, "chart/templates/hpa.yaml", HPA_TPL);
    }

    fn run(root: &Path) -> Retrieved {
        let contents = std::fs::read_to_string(root.join("chart/Chart.yaml")).unwrap();
        retrieve(root, "chart/Chart.yaml", &contents, "snap")
    }

    fn find<'a>(got: &'a Retrieved, unit: &str, key: &str) -> &'a ConfigPacket {
        got.packets
            .iter()
            .find(|p| p.unit == unit && p.key == key)
            .unwrap_or_else(|| panic!("no packet {unit}:{key} in {:?}", got.packets))
    }

    #[test]
    fn committed_values_render_with_the_rendered_confidence_marker() {
        let dir = tempfile::tempdir().unwrap();
        chart_fixture(dir.path());
        let got = run(dir.path());
        // The include placeholder keeps unit identity deterministic.
        let p = find(&got, "deployment:release-mychart", "workload.replicas");
        assert_eq!(p.resolved_value.as_deref(), Some("2"));
        assert_eq!(
            p.resolution,
            Resolution::Rendered,
            "a render is one step removed"
        );
        assert_eq!(p.file_path, "chart/templates/deployment.yaml");
        assert_eq!(p.provenance[0].role, "rendered");
        assert!(
            p.provenance.iter().any(|s| s.file == "chart/values.yaml"),
            "the chain names the committed inputs: {:?}",
            p.provenance
        );
    }

    #[test]
    fn value_pipes_resolve_defaults_from_chart_metadata() {
        let dir = tempfile::tempdir().unwrap();
        chart_fixture(dir.path());
        let got = run(dir.path());
        // tag "" is falsy -> default .Chart.AppVersion "1.16.0" -> a tag pin.
        let pin = find(
            &got,
            "container:deployment/release-mychart/mychart",
            "container.image.pin",
        );
        assert_eq!(pin.resolved_value.as_deref(), Some("tag"));
        let cpu = find(
            &got,
            "container:deployment/release-mychart/mychart",
            "container.resources.limits.cpu",
        );
        assert_eq!(
            cpu.resolved_value.as_deref(),
            Some("200m"),
            "toYaml|nindent renders"
        );
        assert_eq!(cpu.resolution, Resolution::Rendered);
    }

    #[test]
    fn with_blocks_bind_dot_deterministically() {
        let dir = tempfile::tempdir().unwrap();
        chart_fixture(dir.path());
        let got = run(dir.path());
        let live = find(
            &got,
            "container:deployment/release-mychart/mychart",
            "container.liveness-probe",
        );
        assert!(
            live.resolved_value.as_deref().unwrap().contains("/healthz"),
            "{:?}",
            live.resolved_value
        );
        assert_eq!(live.resolution, Resolution::Rendered);
    }

    #[test]
    fn false_if_gates_drop_whole_documents() {
        let dir = tempfile::tempdir().unwrap();
        chart_fixture(dir.path());
        let got = run(dir.path());
        assert!(
            !got.packets.iter().any(|p| p.unit.starts_with("hpa:")),
            "autoscaling.enabled=false renders no HPA: {:?}",
            got.packets
        );
        // Rendered-absent keys still resolve documented platform defaults.
        let tgps = find(
            &got,
            "deployment:release-mychart",
            "pod.termination-grace-period-seconds",
        );
        assert_eq!(tgps.resolved_value.as_deref(), Some("30"));
        assert_eq!(tgps.resolution, Resolution::PlatformDefault);
    }

    #[test]
    fn unvendored_dependencies_abstain_the_whole_chart_with_a_sighting() {
        let dir = tempfile::tempdir().unwrap();
        chart_fixture(dir.path());
        write(
            dir.path(),
            "chart/Chart.yaml",
            "apiVersion: v2\nname: mychart\nversion: 0.1.0\ndependencies:\n  - name: postgresql\n    version: 12.x\n    repository: https://charts.example.com\n",
        );
        let got = run(dir.path());
        assert!(
            got.packets.is_empty(),
            "no packets from an unrenderable chart"
        );
        assert_eq!(got.sightings.len(), 1);
        assert_eq!(got.sightings[0].format, "helm-unvendored-dependencies");
    }

    #[test]
    fn vendored_dependencies_do_not_abstain() {
        let dir = tempfile::tempdir().unwrap();
        chart_fixture(dir.path());
        write(
            dir.path(),
            "chart/Chart.yaml",
            "apiVersion: v2\nname: mychart\nversion: 0.1.0\nappVersion: \"1.16.0\"\ndependencies:\n  - name: postgresql\n    version: 12.x\n",
        );
        write(
            dir.path(),
            "chart/charts/postgresql/Chart.yaml",
            "apiVersion: v2\nname: postgresql\nversion: 12.0.0\n",
        );
        let got = run(dir.path());
        assert!(
            got.packets
                .iter()
                .any(|p| p.unit == "deployment:release-mychart"),
            "an in-tree dependency renders the parent's own templates: {:?}",
            got.sightings
        );
    }

    #[test]
    fn unsupported_constructs_abstain_per_file_with_a_sighting() {
        let dir = tempfile::tempdir().unwrap();
        chart_fixture(dir.path());
        write(
            dir.path(),
            "chart/templates/extra.yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\ndata:\n{{- range .Values.items }}\n  {{ . }}: yes\n{{- end }}\n",
        );
        let got = run(dir.path());
        assert!(
            got.sightings
                .iter()
                .any(|s| s.format == "helm-unrendered-template" && s.file_count == 1),
            "sightings: {:?}",
            got.sightings
        );
        assert!(
            got.packets
                .iter()
                .any(|p| p.unit == "deployment:release-mychart"),
            "other templates still render"
        );
    }

    #[test]
    fn include_on_an_inventoried_value_line_abstains_rather_than_fabricates() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "chart/Chart.yaml", CHART);
        write(dir.path(), "chart/values.yaml", VALUES);
        write(
            dir.path(),
            "chart/templates/deployment.yaml",
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: {{ include \"mychart.image\" . }}\n",
        );
        let contents = std::fs::read_to_string(dir.path().join("chart/Chart.yaml")).unwrap();
        let got = retrieve(dir.path(), "chart/Chart.yaml", &contents, "snap");
        assert!(
            got.packets.is_empty(),
            "a placeholder must never become an image fact: {:?}",
            got.packets
        );
        assert!(got
            .sightings
            .iter()
            .any(|s| s.format == "helm-unrendered-template"));
    }

    #[test]
    fn under_chart_templates_finds_the_owning_chart() {
        let dir = tempfile::tempdir().unwrap();
        chart_fixture(dir.path());
        assert!(under_chart_templates(
            dir.path(),
            "chart/templates/deployment.yaml"
        ));
        assert!(under_chart_templates(
            dir.path(),
            "chart/templates/nested/thing.yaml"
        ));
        assert!(!under_chart_templates(dir.path(), "chart/values.yaml"));
        assert!(
            !under_chart_templates(dir.path(), "elsewhere/templates/x.yaml"),
            "a templates dir without a chart is not helm's"
        );
    }
}
