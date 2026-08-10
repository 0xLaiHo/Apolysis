// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashMap};

use apolysis_accountability::{
    AgentObservationRecord, CollectorHealthProjection, EvidenceBoundary, EvidenceState,
    FindingDecision, FindingKind, ObservationRecordSourceIntegrity, ProjectedLifecycleCounters,
    ProjectionIssueCode, ReviewState,
};

use crate::{StandaloneHtml, ViewerError};

const MAX_VIEWER_OUTPUT_BYTES: usize = 256 * 1024 * 1024;

pub(crate) fn render_record(
    record: &AgentObservationRecord,
) -> Result<StandaloneHtml, ViewerError> {
    let raw_event_targets = record
        .runtime_observations
        .iter()
        .filter_map(|observation| {
            observation
                .raw_event_id
                .as_ref()
                .map(|raw_event_id| (raw_event_id.clone(), observation.source_ordinal))
        })
        .collect::<HashMap<_, _>>();
    let identity_indexes = record
        .runtime_identities
        .iter()
        .enumerate()
        .map(|(index, identity)| (identity.identity_id.clone(), index + 1))
        .collect::<HashMap<_, _>>();
    let event_indexes = category_indexes(record.summary.event_type_counts.keys());
    let relation_indexes = category_indexes(record.summary.relation_counts.keys());
    let default_panel = if !record.findings.is_empty() {
        "findings"
    } else if record.summary.evidence_state != EvidenceState::Complete
        || record.summary.collector_health != CollectorHealthProjection::Healthy
        || record.summary.review_state == ReviewState::Indeterminate
    {
        "collection"
    } else {
        "observations"
    };

    let mut output = String::with_capacity(64 * 1024);
    output.push_str("<!doctype html>\n<html lang=\"en\" data-apolysis-viewer-schema=\"1\" data-theme=\"light\" data-density=\"comfortable\"><head>");
    output.push_str("<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    output.push_str("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; font-src 'none'; connect-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; worker-src 'none'; manifest-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\">");
    output.push_str("<meta name=\"referrer\" content=\"no-referrer\"><title>Apolysis · Agent Run evidence review</title><style>");
    output.push_str(STYLES);
    output.push_str("</style></head>");
    push_formatted(
        &mut output,
        format_args!(
        "<body data-default-panel=\"{default_panel}\"><a class=\"skip-link\" href=\"#investigation\">Skip to investigation</a><div class=\"app-shell\">"
        ),
    );
    render_top_bar(&mut output, record);
    output.push_str("<div class=\"workspace\">");
    render_navigation(&mut output, record);
    output.push_str("<main id=\"investigation\" class=\"investigation\"><div class=\"page-intro\"><div><p class=\"kicker\">Frozen Agent Observation Record v1</p><h1>Evidence, without a verdict.</h1><p class=\"lede\">Review one saved Agent Run locally. Facts remain in source order; collection limits stay visible.</p></div><div class=\"artifact-mode\"><span class=\"mode-dot\"></span>Offline / read-only</div></div>");
    render_state_strip(&mut output, record);
    render_overview(&mut output, record);
    render_findings(&mut output, record, &raw_event_targets);
    render_collection(&mut output, record);
    render_observations(
        &mut output,
        record,
        &event_indexes,
        &relation_indexes,
        &identity_indexes,
    );
    render_identities(&mut output, record, &identity_indexes);
    render_capabilities(&mut output, record);
    output.push_str("</main></div><footer><span>Apolysis saved-run viewer</span><span>No live observer · no runtime socket · no network access</span></footer></div><script>");
    output.push_str(SCRIPT);
    output.push_str("</script></body></html>\n");

    if output.len() > MAX_VIEWER_OUTPUT_BYTES {
        return Err(ViewerError::ArtifactLimitExceeded);
    }
    Ok(StandaloneHtml(output.into_bytes().into_boxed_slice()))
}

fn category_indexes<'a>(values: impl Iterator<Item = &'a String>) -> BTreeMap<String, usize> {
    values
        .enumerate()
        .map(|(index, value)| (value.clone(), index + 1))
        .collect()
}

fn render_top_bar(output: &mut String, record: &AgentObservationRecord) {
    output.push_str("<header class=\"top-bar\"><div class=\"brand\"><span class=\"brand-mark\" aria-hidden=\"true\">A</span><div><strong>Apolysis</strong><span>Agent observability</span></div></div><div class=\"run-context\"><span>Agent Run</span><bdi class=\"fact-text\">");
    push_escaped(output, &record.agent_run_id);
    output.push_str("</bdi></div><div class=\"view-controls\" aria-label=\"View controls\"><button type=\"button\" class=\"control-button\" data-action=\"toggle-density\" aria-label=\"Toggle display density\">Density</button><button type=\"button\" class=\"control-button\" data-action=\"toggle-theme\" aria-label=\"Toggle color theme\">Dark</button></div></header>");
}

fn render_navigation(output: &mut String, record: &AgentObservationRecord) {
    output.push_str("<aside class=\"side-rail\"><div class=\"rail-meta\"><span class=\"meta-label\">Source integrity</span><strong>");
    output.push_str(source_integrity(record.source_integrity));
    output.push_str(
        "</strong><code>/source_integrity</code></div><nav aria-label=\"Investigation sections\">",
    );
    nav_button(output, "overview", "01", "Run summary", None);
    nav_button(
        output,
        "findings",
        "02",
        "Findings",
        Some(record.findings.len()),
    );
    nav_button(
        output,
        "collection",
        "03",
        "Collection limits",
        Some(record.observation_gaps.len() + record.issues.len()),
    );
    nav_button(
        output,
        "observations",
        "04",
        "Observations",
        Some(record.runtime_observations.len()),
    );
    nav_button(
        output,
        "identities",
        "05",
        "Runtime identities",
        Some(record.runtime_identities.len()),
    );
    nav_button(
        output,
        "capabilities",
        "06",
        "Capabilities",
        Some(record.capability_manifests.len()),
    );
    output.push_str("</nav><div class=\"rail-note\"><strong>Interpretation boundary</strong><p>A succeeded operation is not an Agent Run success. No findings reported is not a clean or safe verdict.</p></div></aside>");
}

fn nav_button(output: &mut String, target: &str, number: &str, label: &str, count: Option<usize>) {
    push_formatted(
        output,
        format_args!(
            "<button type=\"button\" class=\"nav-item\" data-panel-target=\"{target}\"><span>{number}</span><strong>{label}</strong>"
        ),
    );
    if let Some(count) = count {
        push_formatted(output, format_args!("<em>{count}</em>"));
    }
    output.push_str("</button>");
}

fn render_state_strip(output: &mut String, record: &AgentObservationRecord) {
    output
        .push_str("<section class=\"state-strip\" aria-label=\"Independent observation states\">");
    state_card(
        output,
        "Evidence State",
        evidence_state(record.summary.evidence_state),
        "/summary/evidence_state",
        "How complete the recorded evidence is.",
    );
    state_card(
        output,
        "Collector Health",
        collector_health(record.summary.collector_health),
        "/summary/collector_health",
        "What the collector reported about itself.",
    );
    state_card(
        output,
        "Review State",
        review_state(record.summary.review_state),
        "/summary/review_state",
        "Whether projected Findings need review.",
    );
    output.push_str("</section>");
}

fn state_card(output: &mut String, label: &str, value: &str, pointer: &str, help: &str) {
    push_formatted(
        output,
        format_args!(
            "<article class=\"state-card state-{value}\"><div><span class=\"state-label\">{label}</span><code>{pointer}</code></div><strong>{value}</strong><p>{help}</p></article>"
        ),
    );
}

fn render_overview(output: &mut String, record: &AgentObservationRecord) {
    panel_start(
        output,
        "overview",
        "Run summary",
        "Projection-level facts and their typed source locations.",
    );
    output.push_str("<div class=\"metric-grid\">");
    summary_metric(
        output,
        "Runtime observations",
        record.summary.runtime_observation_count,
        "/summary/runtime_observation_count",
    );
    summary_metric(
        output,
        "Runtime identities",
        record.summary.runtime_identity_count,
        "/summary/runtime_identity_count",
    );
    summary_metric(
        output,
        "Findings",
        record.summary.finding_count,
        "/summary/finding_count",
    );
    summary_metric(
        output,
        "Observation gap records",
        record.summary.observation_gap_record_count,
        "/summary/observation_gap_record_count",
    );
    summary_metric(
        output,
        "Known missing observations",
        record.summary.known_missing_observation_count,
        "/summary/known_missing_observation_count",
    );
    summary_metric(
        output,
        "Unknown-history boundaries",
        record.summary.unknown_history_boundary_count,
        "/summary/unknown_history_boundary_count",
    );
    output.push_str("</div><div class=\"two-column\"><div class=\"data-card\"><div class=\"card-heading\"><h3>Observed operations</h3><code>/summary/event_type_counts</code></div>");
    render_count_map(output, &record.summary.event_type_counts);
    output.push_str("</div><div class=\"data-card\"><div class=\"card-heading\"><h3>Operation outcomes</h3><code>/summary/outcome_counts</code></div>");
    render_count_map(output, &record.summary.outcome_counts);
    output.push_str("</div><div class=\"data-card\"><div class=\"card-heading\"><h3>Attribution relations</h3><code>/summary/relation_counts</code></div>");
    render_count_map(output, &record.summary.relation_counts);
    output.push_str("</div><div class=\"data-card boundary-card\"><div class=\"card-heading\"><h3>What this view does not claim</h3><span>Domain definition</span></div><p>It does not decide whether an Agent Run was safe, successful, policy-compliant, or remotely submitted. It does not reconstruct raw JSONL.</p></div></div>");
    panel_end(output);
}

fn render_count_map(output: &mut String, counts: &BTreeMap<String, u64>) {
    if counts.is_empty() {
        output.push_str("<p class=\"empty-state\">No values recorded.</p>");
        return;
    }
    output.push_str("<dl class=\"count-list\">");
    for (key, count) in counts {
        output.push_str("<div><dt><bdi class=\"fact-text\">");
        push_escaped(output, key);
        push_formatted(output, format_args!("</bdi></dt><dd>{count}</dd></div>"));
    }
    output.push_str("</dl>");
}

fn summary_metric(output: &mut String, label: &str, value: u64, pointer: &str) {
    push_formatted(
        output,
        format_args!(
            "<article class=\"metric-card\"><span>{label}</span><strong>{value}</strong><code>{pointer}</code></article>"
        ),
    );
}

fn render_findings(
    output: &mut String,
    record: &AgentObservationRecord,
    raw_event_targets: &HashMap<String, u64>,
) {
    panel_start(
        output,
        "findings",
        "Findings",
        "Review projected concerns and follow each evidence reference back to one Runtime Observation.",
    );
    if record.findings.is_empty() {
        output.push_str("<div class=\"empty-state prominent\"><strong>No Finding records are present.</strong><p>This is only the stored Review State; it is not a clean or safety verdict.</p></div>");
    } else {
        output.push_str("<div class=\"stack\">");
        for (index, finding) in record.findings.iter().enumerate() {
            output.push_str("<article class=\"evidence-card searchable\">");
            source_header(
                output,
                finding.source_ordinal,
                &format!("/findings/{index}"),
            );
            output.push_str("<div class=\"finding-title\"><div><span class=\"severity-label\">Review required</span><h3>");
            output.push_str(finding_kind(&finding.kind));
            output.push_str("</h3></div><span class=\"decision\">");
            output.push_str(finding_decision(&finding.decision));
            output.push_str("</span></div><p class=\"finding-reason\"><bdi class=\"fact-text\">");
            push_escaped(output, &finding.reason);
            output.push_str("</bdi></p><dl class=\"fact-grid\"><div><dt>Evidence reference</dt><dd><bdi class=\"fact-text\">");
            push_escaped(output, &finding.evidence_ref);
            output.push_str("</bdi></dd></div><div><dt>Evidence boundary</dt><dd>");
            output.push_str(evidence_boundary(&finding.evidence_boundary));
            output.push_str("</dd></div><div><dt>Runtime</dt><dd><bdi class=\"fact-text\">");
            push_escaped(output, &finding.runtime.runtime);
            output.push_str(
                "</bdi></dd></div><div><dt>Container ID</dt><dd><bdi class=\"fact-text\">",
            );
            optional_text(output, finding.runtime.container_id.as_deref());
            output.push_str("</bdi></dd></div><div><dt>Pod UID</dt><dd><bdi class=\"fact-text\">");
            optional_text(output, finding.runtime.pod_uid.as_deref());
            output.push_str("</bdi></dd></div><div><dt>Cgroup ID</dt><dd class=\"mono-value\">");
            optional_number(output, finding.runtime.cgroup_id);
            output.push_str("</dd></div></dl>");
            if let Some(source_ordinal) = raw_event_targets.get(&finding.evidence_ref) {
                push_formatted(
                    output,
                    format_args!(
                        "<button type=\"button\" class=\"trace-button\" data-evidence-target=\"observation-{source_ordinal}\">Open supporting observation <span>source ordinal {source_ordinal}</span></button>"
                    ),
                );
            } else {
                output.push_str("<p class=\"limitation\">Evidence reference is unresolved in this record. See Collection limits.</p>");
            }
            output.push_str("</article>");
        }
        output.push_str("</div>");
    }
    panel_end(output);
}

fn render_collection(output: &mut String, record: &AgentObservationRecord) {
    panel_start(
        output,
        "collection",
        "Collection limits",
        "Collector lifecycle, loss, gaps, and projection issues remain separate from Findings.",
    );
    let has_limits = record.summary.evidence_state != EvidenceState::Complete
        || record.summary.collector_health != CollectorHealthProjection::Healthy
        || !record.observation_gaps.is_empty()
        || !record.issues.is_empty();
    if has_limits {
        output.push_str("<div class=\"notice notice-limit\"><strong>Evidence limitations are present.</strong><p>Read each stored gap and issue before interpreting the observations.</p></div>");
    } else {
        output.push_str("<div class=\"notice\"><strong>No stored collection limitation was projected.</strong><p>Complete evidence and healthy collection still do not establish safety or Agent Run success.</p></div>");
    }

    output.push_str("<div class=\"section-block\"><div class=\"block-heading\"><h3>Observation Gaps</h3><code>/observation_gaps</code></div>");
    if record.observation_gaps.is_empty() {
        output.push_str("<p class=\"empty-state\">No Observation Gap records.</p>");
    } else {
        output.push_str("<div class=\"stack compact-stack\">");
        for (index, gap) in record.observation_gaps.iter().enumerate() {
            output.push_str("<article class=\"limit-card searchable\">");
            source_header(
                output,
                gap.source_ordinal,
                &format!("/observation_gaps/{index}"),
            );
            output.push_str("<h4><bdi class=\"fact-text\">");
            push_escaped(output, &gap.kind);
            push_formatted(
                output,
                format_args!(
                    "</bdi> <span>count {}</span></h4><p><bdi class=\"fact-text\">",
                    gap.count
                ),
            );
            push_escaped(output, &gap.detail);
            output.push_str("</bdi></p><dl class=\"fact-grid detail-grid\"><div><dt>Operation</dt><dd><bdi class=\"fact-text\">");
            push_escaped(output, &gap.operation);
            output.push_str("</bdi></dd></div></dl>");
            if gap.kind == "late_attach" {
                output.push_str("<p class=\"boundary-note\">Unknown-history Collection Boundary; this count is not a missing-event count.</p>");
            }
            output.push_str("</article>");
        }
        output.push_str("</div>");
    }
    output.push_str("</div><div class=\"section-block\"><div class=\"block-heading\"><h3>Projection issues</h3><code>/issues</code></div>");
    if record.issues.is_empty() {
        output.push_str("<p class=\"empty-state\">No projection issues.</p>");
    } else {
        output.push_str("<div class=\"issue-grid\">");
        for (index, issue) in record.issues.iter().enumerate() {
            push_formatted(
                output,
                format_args!(
                    "<article class=\"issue-card searchable\"><span>issue {}</span><h4>{}</h4><p>Count: {}</p>",
                    index + 1,
                    issue_code(issue.code),
                    issue.count
                ),
            );
            if let Some(ordinal) = issue.source_ordinal {
                push_formatted(output, format_args!("<p>source ordinal {ordinal}</p>"));
            } else {
                output.push_str("<p>Projection-level issue</p>");
            }
            push_formatted(
                output,
                format_args!("<code>/issues/{index}</code></article>"),
            );
        }
        output.push_str("</div>");
    }
    output.push_str("</div><div class=\"section-block\"><div class=\"block-heading\"><h3>Collector lifecycle</h3><code>/collector_lifecycle</code></div>");
    if record.collector_lifecycle.is_empty() {
        output.push_str("<p class=\"empty-state\">No collector lifecycle records.</p>");
    } else {
        output.push_str("<div class=\"timeline\">");
        for (index, lifecycle) in record.collector_lifecycle.iter().enumerate() {
            output.push_str("<article class=\"timeline-row searchable\"><div class=\"timeline-rail\"><span></span></div><div class=\"timeline-body\">");
            source_header(
                output,
                lifecycle.source_ordinal,
                &format!("/collector_lifecycle/{index}"),
            );
            push_formatted(
                output,
                format_args!(
                    "<h4>{} · {}</h4><p class=\"mono-value\">timestamp {}</p>",
                    lifecycle.state.as_str(),
                    lifecycle.health.as_str(),
                    lifecycle.timestamp_unix_ms
                ),
            );
            output.push_str("<dl class=\"fact-grid detail-grid\"><div><dt>Collector instance</dt><dd><bdi class=\"fact-text\">");
            push_escaped(output, &lifecycle.collector_instance_id);
            output.push_str("</bdi></dd></div></dl>");
            if let Some(reason) = lifecycle.stop_reason {
                push_formatted(
                    output,
                    format_args!("<p>Stop reason: {}</p>", reason.as_str()),
                );
            }
            render_lifecycle_counters(output, lifecycle.counters);
            output.push_str("</div></article>");
        }
        output.push_str("</div>");
    }
    output.push_str("</div>");
    panel_end(output);
}

fn render_lifecycle_counters(output: &mut String, counters: ProjectedLifecycleCounters) {
    output.push_str("<details><summary>Collector counters</summary><dl class=\"counter-grid\">");
    counter(output, "reserve failures", counters.global_reserve_failures);
    counter(output, "map pressure", counters.global_map_pressure);
    counter(output, "ABI mismatches", counters.global_abi_mismatches);
    counter(output, "decode failures", counters.global_decode_failures);
    counter(output, "truncations", counters.global_truncations);
    counter(output, "missing entries", counters.scope_missing_entries);
    counter(output, "missing exits", counters.scope_missing_exits);
    counter(output, "scope pending", counters.scope_pending);
    output.push_str("</dl></details>");
}

fn counter(output: &mut String, label: &str, value: u64) {
    push_formatted(
        output,
        format_args!("<div><dt>{label}</dt><dd>{value}</dd></div>"),
    );
}

fn render_observations(
    output: &mut String,
    record: &AgentObservationRecord,
    event_indexes: &BTreeMap<String, usize>,
    relation_indexes: &BTreeMap<String, usize>,
    identity_indexes: &HashMap<String, usize>,
) {
    panel_start(
        output,
        "observations",
        "Runtime Observations",
        "Canonical order is source_ordinal. Timestamps are display facts and never reorder this rail.",
    );
    output.push_str("<div class=\"filter-bar\"><label class=\"search-control\"><span>Search facts</span><input type=\"search\" data-action=\"search-observations\" placeholder=\"actor, resource, event…\" autocomplete=\"off\"></label><label><span>Event type</span><select data-action=\"filter-event\"><option value=\"0\">All event types</option>");
    for (event_type, index) in event_indexes {
        push_formatted(output, format_args!("<option value=\"{index}\">"));
        push_escaped(output, event_type);
        output.push_str("</option>");
    }
    output.push_str("</select></label><label><span>Relation</span><select data-action=\"filter-relation\"><option value=\"0\">All relations</option>");
    for (relation, index) in relation_indexes {
        push_formatted(output, format_args!("<option value=\"{index}\">"));
        push_escaped(output, relation);
        output.push_str("</option>");
    }
    output.push_str("</select></label><button type=\"button\" class=\"clear-button\" data-action=\"clear-observation-filters\">Clear</button></div><p class=\"filter-status\" data-filter-status aria-live=\"polite\"></p>");
    if record.runtime_observations.is_empty() {
        output.push_str("<p class=\"empty-state prominent\">No Runtime Observation records.</p>");
    } else {
        output.push_str("<div class=\"observation-rail\">");
        for (index, observation) in record.runtime_observations.iter().enumerate() {
            let event_index = event_indexes[observation.event_type.as_str()];
            let relation_index = relation_indexes[observation.relation_status.as_str()];
            let identity_index = observation
                .runtime_identity_id
                .as_ref()
                .and_then(|identity_id| identity_indexes.get(identity_id))
                .copied()
                .unwrap_or(0);
            push_formatted(
                output,
                format_args!(
                    "<article id=\"observation-{}\" class=\"observation-card searchable\" data-observation data-event-index=\"{event_index}\" data-relation-index=\"{relation_index}\" data-identity-index=\"{identity_index}\"><div class=\"source-rail\"><span>{}</span></div><div class=\"observation-body\">",
                    observation.source_ordinal,
                    observation.source_ordinal
                ),
            );
            source_header(
                output,
                observation.source_ordinal,
                &format!("/runtime_observations/{index}"),
            );
            output.push_str("<div class=\"observation-title\"><div><span class=\"event-source\"><bdi class=\"fact-text\">");
            push_escaped(output, &observation.event_source);
            output.push_str("</bdi></span><h3><bdi class=\"fact-text\">");
            push_escaped(output, &observation.event_type);
            output.push_str("</bdi></h3></div><span class=\"outcome\">");
            if let Some(outcome) = &observation.outcome {
                push_escaped(output, outcome);
            } else {
                output.push_str("not_recorded");
            }
            output.push_str("</span></div><p class=\"action-line\"><bdi class=\"fact-text\">");
            push_escaped(output, &observation.actor);
            output.push_str("</bdi> <strong>→</strong> <bdi class=\"fact-text\">");
            push_escaped(output, &observation.action);
            output.push_str("</bdi> <strong>→</strong> <bdi class=\"fact-text resource\">");
            push_escaped(output, &observation.resource);
            output.push_str("</bdi></p><dl class=\"fact-grid observation-facts\"><div><dt>Timestamp (Unix ms)</dt><dd class=\"mono-value\">");
            push_formatted(output, format_args!("{}", observation.timestamp_unix_ms));
            output.push_str(
                "</dd></div><div><dt>Attribution relation</dt><dd><bdi class=\"fact-text\">",
            );
            push_escaped(output, &observation.relation_status);
            output.push_str(
                "</bdi></dd></div><div><dt>PID / reported PPID</dt><dd class=\"mono-value\">",
            );
            push_formatted(
                output,
                format_args!("{} / {}", observation.pid, observation.ppid),
            );
            output.push_str("</dd></div><div><dt>Raw event ID</dt><dd><bdi class=\"fact-text\">");
            if let Some(raw_event_id) = &observation.raw_event_id {
                push_escaped(output, raw_event_id);
            } else {
                output.push_str("not_recorded");
            }
            output.push_str("</bdi></dd></div></dl><details><summary>Source detail</summary><dl class=\"fact-grid detail-grid\"><div><dt>Relation reason</dt><dd><bdi class=\"fact-text\">");
            push_escaped(output, &observation.relation_reason);
            output
                .push_str("</bdi></dd></div><div><dt>Return / errno</dt><dd class=\"mono-value\">");
            optional_number(output, observation.return_value);
            output.push_str(" / ");
            optional_number(output, observation.errno);
            output
                .push_str("</dd></div><div><dt>Runtime identity</dt><dd><bdi class=\"fact-text\">");
            if let Some(identity_id) = &observation.runtime_identity_id {
                push_escaped(output, identity_id);
            } else {
                output.push_str("unattributed");
            }
            output
                .push_str("</bdi></dd></div><div><dt>Executable</dt><dd><bdi class=\"fact-text\">");
            if let Some(executable) = &observation.process_executable {
                push_escaped(output, executable);
            } else {
                output.push_str("not_recorded");
            }
            output.push_str(
                "</bdi></dd></div><div><dt>Container ID</dt><dd><bdi class=\"fact-text\">",
            );
            optional_text(output, observation.container_id.as_deref());
            output
                .push_str("</bdi></dd></div><div><dt>Cgroup ID</dt><dd><bdi class=\"fact-text\">");
            optional_text(output, observation.cgroup_id.as_deref());
            output.push_str(
                "</bdi></dd></div><div><dt>Process started (Unix ms)</dt><dd class=\"mono-value\">",
            );
            optional_number(output, observation.process_started_at_unix_ms);
            output.push_str(
                "</dd></div><div><dt>Parent process generation</dt><dd class=\"mono-value\">",
            );
            optional_number(output, observation.parent_process_generation);
            output.push_str(
                "</dd></div><div><dt>Parent exec generation</dt><dd class=\"mono-value\">",
            );
            optional_number(output, observation.parent_exec_generation);
            output.push_str("</dd></div></dl></details></div></article>");
        }
        output.push_str("</div>");
    }
    panel_end(output);
}

fn optional_number<T: std::fmt::Display>(output: &mut String, value: Option<T>) {
    if let Some(value) = value {
        push_formatted(output, format_args!("{value}"));
    } else {
        output.push_str("not_recorded");
    }
}

fn optional_text(output: &mut String, value: Option<&str>) {
    if let Some(value) = value {
        push_escaped(output, value);
    } else {
        output.push_str("not_recorded");
    }
}

fn render_identities(
    output: &mut String,
    record: &AgentObservationRecord,
    identity_indexes: &HashMap<String, usize>,
) {
    panel_start(
        output,
        "identities",
        "Runtime Identities",
        "Exact identity roster for this Agent Run; parent relationships are not inferred.",
    );
    output.push_str("<div class=\"notice identity-boundary\"><strong>No canonical process tree in schema v1.</strong><p>The record retains exact Runtime Identities and reported PID/PPID fields, but not enough parent identity to construct authoritative edges.</p></div>");
    if record.runtime_identities.is_empty() {
        output.push_str(
            "<p class=\"empty-state prominent\">No exact Runtime Identities were projected.</p>",
        );
    } else {
        output.push_str("<div class=\"identity-grid\">");
        for (index, identity) in record.runtime_identities.iter().enumerate() {
            let identity_index = identity_indexes[identity.identity_id.as_str()];
            output.push_str("<article class=\"identity-card searchable\"><div class=\"identity-heading\"><span>Exact Runtime Identity</span><strong>PID ");
            push_formatted(output, format_args!("{}", identity.pid));
            output.push_str("</strong></div><h3><bdi class=\"fact-text\">");
            push_escaped(output, &identity.identity_id);
            output.push_str("</bdi></h3><dl class=\"fact-grid\"><div><dt>Host boot ID</dt><dd><bdi class=\"fact-text\">");
            push_escaped(output, &identity.host_boot_id);
            push_formatted(
                output,
                format_args!(
                    "</bdi></dd></div><div><dt>Scope / process generation</dt><dd class=\"mono-value\">{} / {}</dd></div><div><dt>Process start ns</dt><dd class=\"mono-value\">{}</dd></div><div><dt>Exec generation</dt><dd class=\"mono-value\">{}</dd></div><div><dt>Source span</dt><dd class=\"mono-value\">{}–{}</dd></div><div><dt>Observation count</dt><dd class=\"mono-value\">{}</dd></div></dl>",
                    identity.scope_generation,
                    identity.process_generation,
                    identity.process_start_time_ns,
                    identity.exec_generation,
                    identity.first_source_ordinal,
                    identity.last_source_ordinal,
                    identity.observation_count
                ),
            );
            push_formatted(
                output,
                format_args!(
                    "<button type=\"button\" class=\"trace-button\" data-identity-target=\"{identity_index}\">Filter supporting observations</button><code>/runtime_identities/{index}</code></article>"
                ),
            );
        }
        output.push_str("</div>");
    }
    panel_end(output);
}

fn render_capabilities(output: &mut String, record: &AgentObservationRecord) {
    panel_start(
        output,
        "capabilities",
        "Collector Capabilities",
        "What each stored collector manifest declared it could observe under its scope and privacy profile.",
    );
    if record.capability_manifests.is_empty() {
        output.push_str("<div class=\"empty-state prominent\"><strong>No capability manifest.</strong><p>Treat the observation surface as incomplete; see the matching projection issue.</p></div>");
    } else {
        for (index, manifest) in record.capability_manifests.iter().enumerate() {
            output.push_str("<article class=\"capability-card\">");
            source_header(
                output,
                manifest.source_ordinal,
                &format!("/capability_manifests/{index}"),
            );
            output.push_str("<div class=\"capability-heading\"><div><span>Collector</span><h3><bdi class=\"fact-text\">");
            push_escaped(output, &manifest.collector);
            output.push_str("</bdi></h3></div><div><span>Version</span><bdi class=\"fact-text\">");
            push_escaped(output, &manifest.collector_version);
            output.push_str("</bdi></div></div><dl class=\"fact-grid\"><div><dt>Observation scope</dt><dd><bdi class=\"fact-text\">");
            push_escaped(output, &manifest.observation_scope);
            output.push_str(
                "</bdi></dd></div><div><dt>Privacy profile</dt><dd><bdi class=\"fact-text\">",
            );
            push_escaped(output, &manifest.privacy_profile);
            push_formatted(
                output,
                format_args!(
                    "</bdi></dd></div><div><dt>Kernel ABI / record size</dt><dd class=\"mono-value\">{} / {}</dd></div><div><dt>Timestamp</dt><dd class=\"mono-value\">{}</dd></div></dl><div class=\"capability-table\"><div class=\"table-row table-head\"><span>Operation</span><span>Event sources</span><span>Outcomes</span></div>",
                    manifest.kernel_abi_version,
                    manifest.kernel_record_size,
                    manifest.timestamp_unix_ms
                ),
            );
            for capability in &manifest.capabilities {
                output.push_str(
                    "<div class=\"table-row searchable\"><strong><bdi class=\"fact-text\">",
                );
                push_escaped(output, &capability.operation);
                output.push_str("</bdi></strong><span>");
                escaped_join(output, &capability.event_sources);
                output.push_str("</span><span>");
                escaped_join(output, &capability.outcomes);
                output.push_str("</span></div>");
            }
            output.push_str("</div></article>");
        }
    }
    panel_end(output);
}

fn escaped_join(output: &mut String, values: &[String]) {
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            output.push_str(" · ");
        }
        output.push_str("<bdi class=\"fact-text\">");
        push_escaped(output, value);
        output.push_str("</bdi>");
    }
}

fn source_header(output: &mut String, ordinal: u64, pointer: &str) {
    push_formatted(
        output,
        format_args!(
            "<div class=\"source-header\"><span>source ordinal {ordinal}</span><code>{pointer}</code></div>"
        ),
    );
}

fn panel_start(output: &mut String, id: &str, title: &str, description: &str) {
    push_formatted(
        output,
        format_args!(
            "<section class=\"panel\" data-panel=\"{id}\" aria-labelledby=\"panel-{id}-title\"><div class=\"panel-heading\"><div><span class=\"section-index\">Investigation view</span><h2 id=\"panel-{id}-title\">{title}</h2></div><p>{description}</p></div>"
        ),
    );
}

fn panel_end(output: &mut String) {
    output.push_str("</section>");
}

fn push_formatted(output: &mut String, arguments: std::fmt::Arguments<'_>) {
    // `fmt::Write` for `String` is infallible; discard its formal error channel
    // instead of introducing a panic-only branch into the renderer.
    let _ = std::fmt::Write::write_fmt(output, arguments);
}

fn push_escaped(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            character if character.is_control() || is_bidi_control(character) => {
                push_formatted(output, format_args!("\\u{{{:04x}}}", character as u32));
            }
            character => output.push(character),
        }
    }
}

fn is_bidi_control(character: char) -> bool {
    matches!(
        character,
        '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
    )
}

fn evidence_state(value: EvidenceState) -> &'static str {
    match value {
        EvidenceState::Complete => "complete",
        EvidenceState::Active => "active",
        EvidenceState::Incomplete => "incomplete",
        EvidenceState::Failed => "failed",
        EvidenceState::Indeterminate => "indeterminate",
    }
}

fn collector_health(value: CollectorHealthProjection) -> &'static str {
    match value {
        CollectorHealthProjection::Healthy => "healthy",
        CollectorHealthProjection::Degraded => "degraded",
        CollectorHealthProjection::Failed => "failed",
        CollectorHealthProjection::Unknown => "unknown",
    }
}

fn review_state(value: ReviewState) -> &'static str {
    match value {
        ReviewState::RequiresReview => "requires_review",
        ReviewState::NoFindingsReported => "no_findings_reported",
        ReviewState::Indeterminate => "indeterminate",
    }
}

fn source_integrity(value: ObservationRecordSourceIntegrity) -> &'static str {
    match value {
        ObservationRecordSourceIntegrity::UnverifiedPlainJsonl => "unverified_plain_jsonl",
        ObservationRecordSourceIntegrity::VerifiedHashChain => "verified_hash_chain",
        ObservationRecordSourceIntegrity::Mixed => "mixed",
    }
}

fn finding_kind(value: &FindingKind) -> &'static str {
    match value {
        FindingKind::MissingIntent => "missing_intent",
        FindingKind::UnobservedIntent => "unobserved_intent",
        FindingKind::UndeclaredAction => "undeclared_action",
        FindingKind::CredentialRead => "credential_read",
        FindingKind::WorkspaceBoundary => "workspace_boundary",
        FindingKind::UnknownEgress => "unknown_egress",
        FindingKind::DangerousCommand => "dangerous_command",
        FindingKind::ServiceAccountTokenRead => "service_account_token_read",
    }
}

fn finding_decision(value: &FindingDecision) -> &'static str {
    match value {
        FindingDecision::Notify => "notify",
        FindingDecision::Review => "review",
    }
}

fn evidence_boundary(value: &EvidenceBoundary) -> &'static str {
    match value {
        EvidenceBoundary::HostBoundary => "host_boundary",
        EvidenceBoundary::GuestSemantic => "guest_semantic",
    }
}

fn issue_code(value: ProjectionIssueCode) -> &'static str {
    match value {
        ProjectionIssueCode::MissingCapability => "missing_capability",
        ProjectionIssueCode::UnsupportedCapability => "unsupported_capability",
        ProjectionIssueCode::MissingLifecycleStart => "missing_lifecycle_start",
        ProjectionIssueCode::MissingLifecycleTerminal => "missing_lifecycle_terminal",
        ProjectionIssueCode::CollectorLoss => "collector_loss",
        ProjectionIssueCode::CollectorDiagnostic => "collector_diagnostic",
        ProjectionIssueCode::ObservationGap => "observation_gap",
        ProjectionIssueCode::UnsupportedObservation => "unsupported_observation",
        ProjectionIssueCode::UnsupportedOutcome => "unsupported_outcome",
        ProjectionIssueCode::UnknownRecordType => "unknown_record_type",
        ProjectionIssueCode::SourceIntegrityFinding => "source_integrity_finding",
        ProjectionIssueCode::NoRuntimeObservations => "no_runtime_observations",
        ProjectionIssueCode::UnresolvedFindingEvidence => "unresolved_finding_evidence",
    }
}

const STYLES: &str = r#"
:root {
  color-scheme: light;
  --canvas: #eceae3;
  --surface: #f8f7f2;
  --surface-raised: #fffef9;
  --ink: #19221f;
  --ink-soft: #5e6964;
  --line: #cbcfc7;
  --line-strong: #9da69f;
  --nav: #17211e;
  --nav-ink: #eef0e8;
  --accent: #e2603f;
  --accent-soft: #f8dacf;
  --lime: #bed85a;
  --amber: #e6b450;
  --red: #d95847;
  --blue: #6aa8ae;
  --shadow: 0 18px 60px rgba(31, 42, 37, .08);
  --panel-pad: 30px;
  --row-pad: 22px;
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --canvas: #101614;
  --surface: #17201d;
  --surface-raised: #1d2824;
  --ink: #edf0e8;
  --ink-soft: #a6b1ab;
  --line: #35413b;
  --line-strong: #536159;
  --nav: #0b100f;
  --nav-ink: #edf0e8;
  --accent-soft: #542d23;
  --shadow: 0 18px 60px rgba(0, 0, 0, .28);
}
:root[data-density="compact"] { --panel-pad: 20px; --row-pad: 14px; }
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body { margin: 0; min-width: 320px; color: var(--ink); background: var(--canvas); font: 14px/1.55 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
button, input, select { font: inherit; }
button { color: inherit; }
h1, h2, h3, h4, p, dl { margin-top: 0; }
h1 { max-width: 760px; margin-bottom: 16px; font: 720 clamp(38px, 5vw, 68px)/.98 Georgia, ui-serif, serif; letter-spacing: -.045em; }
h2 { margin-bottom: 0; font: 680 clamp(28px, 3vw, 42px)/1 Georgia, ui-serif, serif; letter-spacing: -.025em; }
h3 { font-size: 20px; line-height: 1.2; }
h4 { font-size: 15px; }
code, .mono-value { font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace; font-variant-numeric: tabular-nums; }
code { color: var(--ink-soft); font-size: 11px; overflow-wrap: anywhere; }
.fact-text { unicode-bidi: plaintext; overflow-wrap: anywhere; }
.skip-link { position: fixed; left: 12px; top: -80px; z-index: 99; padding: 10px 14px; color: var(--nav); background: var(--lime); }
.skip-link:focus { top: 12px; }
.app-shell { min-height: 100vh; }
.top-bar { position: sticky; top: 0; z-index: 20; min-height: 72px; display: grid; grid-template-columns: 270px 1fr auto; align-items: center; gap: 20px; padding: 10px 24px; color: var(--nav-ink); background: var(--nav); border-bottom: 1px solid #35413b; }
.brand { display: flex; align-items: center; gap: 12px; }
.brand-mark { width: 36px; height: 36px; display: grid; place-items: center; color: var(--nav); background: var(--lime); font: 800 20px/1 Georgia, serif; }
.brand div { display: grid; }
.brand span:last-child, .run-context span { color: #9eaaa4; font-size: 11px; letter-spacing: .08em; text-transform: uppercase; }
.run-context { min-width: 0; display: flex; gap: 12px; align-items: baseline; }
.run-context bdi { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: "SFMono-Regular", Consolas, monospace; }
.view-controls { display: flex; gap: 8px; }
.control-button, .clear-button { border: 1px solid #536159; background: transparent; padding: 8px 12px; cursor: pointer; }
.control-button:hover, .control-button:focus-visible { border-color: var(--lime); color: var(--lime); }
.workspace { width: min(1540px, 100%); margin: 0 auto; display: grid; grid-template-columns: 270px minmax(0, 1fr); }
.side-rail { position: sticky; top: 72px; height: calc(100vh - 72px); padding: 28px 18px; color: var(--nav-ink); background: var(--nav); overflow: auto; }
.rail-meta { margin: 0 8px 26px; padding: 14px 0 18px; display: grid; gap: 4px; border-bottom: 1px solid #35413b; }
.rail-meta strong { overflow-wrap: anywhere; font-family: "SFMono-Regular", Consolas, monospace; font-size: 12px; }
.rail-meta code { color: #8c9892; }
.meta-label { color: #9eaaa4; font-size: 10px; letter-spacing: .12em; text-transform: uppercase; }
.side-rail nav { display: grid; gap: 5px; }
.nav-item { width: 100%; min-height: 48px; display: grid; grid-template-columns: 30px 1fr auto; align-items: center; gap: 8px; padding: 9px 10px; color: #b9c2bd; background: transparent; border: 0; border-left: 2px solid transparent; text-align: left; cursor: pointer; }
.nav-item > span { color: #78847e; font: 10px/1 "SFMono-Regular", monospace; }
.nav-item strong { font-weight: 580; }
.nav-item em { min-width: 25px; padding: 2px 6px; color: #9eaaa4; background: #27332e; border-radius: 999px; font: normal 10px/1.4 "SFMono-Regular", monospace; text-align: center; }
.nav-item:hover, .nav-item:focus-visible, .nav-item.is-active { color: #fff; background: #222e2a; border-left-color: var(--accent); }
.rail-note { margin: 34px 8px 0; padding: 16px; color: #aeb8b2; background: #202b27; border: 1px solid #35413b; }
.rail-note strong { color: var(--lime); font-size: 11px; letter-spacing: .08em; text-transform: uppercase; }
.rail-note p { margin: 9px 0 0; font-size: 12px; }
.investigation { min-width: 0; padding: 50px clamp(22px, 4vw, 64px) 80px; }
.page-intro { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 30px; align-items: end; padding-bottom: 32px; }
.kicker, .section-index { margin-bottom: 10px; color: var(--accent); font-size: 10px; font-weight: 750; letter-spacing: .14em; text-transform: uppercase; }
.lede { max-width: 680px; margin-bottom: 0; color: var(--ink-soft); font-size: 17px; }
.artifact-mode { display: flex; align-items: center; gap: 8px; padding: 9px 12px; background: var(--surface); border: 1px solid var(--line); font-family: "SFMono-Regular", monospace; font-size: 11px; white-space: nowrap; }
.mode-dot { width: 8px; height: 8px; background: var(--lime); border-radius: 50%; box-shadow: 0 0 0 4px color-mix(in srgb, var(--lime) 20%, transparent); }
.state-strip { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; margin-bottom: 26px; }
.state-card { min-height: 176px; display: flex; flex-direction: column; justify-content: space-between; padding: 20px; color: var(--nav-ink); background: var(--nav); border-top: 4px solid var(--line-strong); box-shadow: var(--shadow); }
.state-card > div { display: flex; justify-content: space-between; gap: 10px; }
.state-card code { color: #8f9b95; }
.state-label { color: #bac3be; font-size: 11px; letter-spacing: .08em; text-transform: uppercase; }
.state-card strong { margin: 18px 0 10px; font: 640 clamp(18px, 2.2vw, 28px)/1.1 "SFMono-Regular", monospace; overflow-wrap: anywhere; }
.state-card p { margin-bottom: 0; color: #9da9a3; font-size: 12px; }
.state-complete, .state-healthy { border-top-color: var(--lime); }
.state-requires_review, .state-incomplete, .state-degraded, .state-indeterminate, .state-unknown { border-top-color: var(--amber); }
.state-failed { border-top-color: var(--red); }
.panel { margin-bottom: 22px; padding: var(--panel-pad); background: var(--surface); border: 1px solid var(--line); box-shadow: var(--shadow); }
.enhanced .panel[hidden] { display: none; }
.panel-heading { display: grid; grid-template-columns: minmax(260px, .8fr) minmax(300px, 1.2fr); gap: 32px; align-items: end; margin: calc(var(--panel-pad) * -1) calc(var(--panel-pad) * -1) 26px; padding: var(--panel-pad); border-bottom: 1px solid var(--line); }
.panel-heading p { margin-bottom: 0; color: var(--ink-soft); }
.metric-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1px; margin-bottom: 20px; background: var(--line); border: 1px solid var(--line); }
.metric-card { min-height: 132px; padding: 18px; display: grid; align-content: space-between; background: var(--surface-raised); }
.metric-card span { color: var(--ink-soft); }
.metric-card strong { margin: 14px 0; font: 650 34px/1 "SFMono-Regular", monospace; }
.two-column { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.data-card, .evidence-card, .limit-card, .identity-card, .capability-card { padding: var(--row-pad); background: var(--surface-raised); border: 1px solid var(--line); }
.card-heading, .block-heading, .source-header { display: flex; justify-content: space-between; gap: 16px; align-items: baseline; }
.card-heading { padding-bottom: 13px; border-bottom: 1px solid var(--line); }
.card-heading h3 { margin-bottom: 0; }
.card-heading span { color: var(--ink-soft); font-size: 11px; text-transform: uppercase; }
.count-list { margin-bottom: 0; }
.count-list div { display: flex; justify-content: space-between; gap: 20px; padding: 10px 0; border-bottom: 1px solid var(--line); }
.count-list div:last-child { border-bottom: 0; }
.count-list dd { margin: 0; font-family: "SFMono-Regular", monospace; }
.boundary-card { border-left: 4px solid var(--amber); }
.stack { display: grid; gap: 14px; }
.compact-stack { gap: 9px; }
.source-header { margin: calc(var(--row-pad) * -.25) 0 18px; padding-bottom: 10px; border-bottom: 1px solid var(--line); color: var(--ink-soft); font: 10px/1.4 "SFMono-Regular", monospace; letter-spacing: .06em; text-transform: uppercase; }
.finding-title, .observation-title, .identity-heading, .capability-heading { display: flex; justify-content: space-between; gap: 20px; align-items: flex-start; }
.finding-title h3, .observation-title h3 { margin: 5px 0 14px; }
.severity-label, .event-source, .identity-heading span, .capability-heading span { color: var(--ink-soft); font-size: 10px; letter-spacing: .1em; text-transform: uppercase; }
.decision, .outcome { padding: 5px 8px; color: var(--nav); background: var(--amber); font: 700 10px/1.2 "SFMono-Regular", monospace; text-transform: uppercase; }
.finding-reason { max-width: 820px; font-size: 18px; }
.fact-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; }
.fact-grid div { min-width: 0; padding-top: 10px; border-top: 1px solid var(--line); }
.fact-grid dt { color: var(--ink-soft); font-size: 10px; letter-spacing: .05em; text-transform: uppercase; }
.fact-grid dd { margin: 5px 0 0; overflow-wrap: anywhere; }
.trace-button { width: 100%; margin-top: 18px; padding: 12px 14px; display: flex; justify-content: space-between; gap: 12px; color: var(--ink); background: transparent; border: 1px solid var(--line-strong); cursor: pointer; text-align: left; }
.trace-button:hover, .trace-button:focus-visible { border-color: var(--accent); background: var(--accent-soft); }
.trace-button span { color: var(--ink-soft); font-family: "SFMono-Regular", monospace; font-size: 11px; }
.limitation, .boundary-note { margin: 16px 0 0; padding: 10px 12px; background: var(--accent-soft); border-left: 3px solid var(--accent); }
.notice { margin-bottom: 22px; padding: 16px 18px; background: var(--surface-raised); border: 1px solid var(--line); border-left: 4px solid var(--lime); }
.notice-limit { border-left-color: var(--amber); }
.notice p { margin: 5px 0 0; color: var(--ink-soft); }
.section-block { margin-top: 28px; }
.block-heading { margin-bottom: 12px; }
.block-heading h3 { margin-bottom: 0; }
.issue-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 9px; }
.issue-card { padding: 15px; background: var(--surface-raised); border-top: 3px solid var(--amber); }
.issue-card > span { color: var(--ink-soft); font: 10px/1.2 "SFMono-Regular", monospace; text-transform: uppercase; }
.issue-card h4 { margin: 8px 0; overflow-wrap: anywhere; }
.issue-card p { margin-bottom: 4px; }
.timeline-row { display: grid; grid-template-columns: 22px minmax(0, 1fr); }
.timeline-rail { position: relative; }
.timeline-rail::before { content: ""; position: absolute; left: 7px; top: 0; bottom: 0; width: 1px; background: var(--line-strong); }
.timeline-rail span { position: relative; z-index: 1; display: block; width: 15px; height: 15px; margin-top: 5px; background: var(--surface); border: 3px solid var(--blue); border-radius: 50%; }
.timeline-body { padding: 0 0 24px 12px; }
.timeline-body h4 { margin-bottom: 6px; }
details { margin-top: 14px; }
summary { color: var(--ink-soft); cursor: pointer; font-weight: 600; }
.counter-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1px; margin: 12px 0 0; background: var(--line); }
.counter-grid div { padding: 9px; background: var(--surface-raised); }
.counter-grid dt { color: var(--ink-soft); font-size: 10px; }
.counter-grid dd { margin: 4px 0 0; font-family: "SFMono-Regular", monospace; }
.filter-bar { display: grid; grid-template-columns: minmax(220px, 1fr) 190px 170px auto; gap: 10px; align-items: end; margin-bottom: 8px; }
.filter-bar label { display: grid; gap: 5px; color: var(--ink-soft); font-size: 10px; letter-spacing: .06em; text-transform: uppercase; }
.filter-bar input, .filter-bar select { width: 100%; min-height: 40px; padding: 8px 10px; color: var(--ink); background: var(--surface-raised); border: 1px solid var(--line-strong); }
.clear-button { min-height: 40px; color: var(--ink); border-color: var(--line-strong); }
.filter-status { min-height: 22px; margin-bottom: 10px; color: var(--ink-soft); font-family: "SFMono-Regular", monospace; font-size: 11px; }
.observation-rail { position: relative; display: grid; gap: 10px; }
.observation-card { display: grid; grid-template-columns: 54px minmax(0, 1fr); background: var(--surface-raised); border: 1px solid var(--line); scroll-margin-top: 100px; }
.source-rail { display: grid; place-items: start center; padding-top: var(--row-pad); color: var(--ink-soft); background: color-mix(in srgb, var(--canvas) 68%, var(--surface)); border-right: 1px solid var(--line); font: 11px/1 "SFMono-Regular", monospace; }
.source-rail span { writing-mode: vertical-rl; transform: rotate(180deg); }
.observation-body { min-width: 0; padding: var(--row-pad); }
.action-line { margin-bottom: 20px; font-size: 16px; }
.resource { color: var(--accent); }
.observation-facts { grid-template-columns: repeat(4, minmax(0, 1fr)); }
.detail-grid { margin-top: 10px; grid-template-columns: repeat(2, minmax(0, 1fr)); }
.observation-card.is-targeted { outline: 3px solid var(--accent); outline-offset: 2px; }
.identity-boundary { border-left-color: var(--blue); }
.identity-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
.identity-heading strong { font: 650 21px/1 "SFMono-Regular", monospace; }
.identity-card h3 { margin: 18px 0; }
.identity-card > code { display: block; margin-top: 14px; }
.capability-card + .capability-card { margin-top: 14px; }
.capability-heading { margin-bottom: 18px; }
.capability-heading h3 { margin: 3px 0 0; }
.capability-heading > div:last-child { display: grid; text-align: right; }
.capability-table { margin-top: 20px; border: 1px solid var(--line); }
.table-row { display: grid; grid-template-columns: minmax(160px, .7fr) 1.5fr 1fr; gap: 16px; padding: 11px 13px; border-bottom: 1px solid var(--line); }
.table-row:last-child { border-bottom: 0; }
.table-head { color: var(--ink-soft); background: var(--canvas); font-size: 10px; letter-spacing: .06em; text-transform: uppercase; }
.empty-state { margin: 0; color: var(--ink-soft); }
.empty-state.prominent { padding: 24px; background: var(--surface-raised); border: 1px dashed var(--line-strong); }
.empty-state.prominent p { margin: 6px 0 0; }
footer { min-height: 70px; display: flex; justify-content: space-between; gap: 20px; align-items: center; padding: 18px 32px; color: #9da9a3; background: var(--nav); font-size: 11px; letter-spacing: .05em; text-transform: uppercase; }
@media (max-width: 1100px) {
  .workspace { grid-template-columns: 220px minmax(0, 1fr); }
  .top-bar { grid-template-columns: 220px 1fr auto; }
  .side-rail { padding-inline: 12px; }
  .metric-grid, .issue-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .filter-bar { grid-template-columns: 1fr 1fr; }
  .search-control { grid-column: 1 / -1; }
  .observation-facts { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 780px) {
  .top-bar { position: static; grid-template-columns: 1fr auto; }
  .run-context { grid-column: 1 / -1; grid-row: 2; }
  .workspace { display: block; }
  .side-rail { position: static; width: 100%; height: auto; padding: 14px; }
  .side-rail nav { grid-template-columns: repeat(2, 1fr); }
  .rail-meta, .rail-note { display: none; }
  .investigation { padding: 30px 14px 54px; }
  .page-intro, .panel-heading, .two-column { grid-template-columns: 1fr; }
  .artifact-mode { justify-self: start; }
  .state-strip, .metric-grid, .issue-grid, .identity-grid { grid-template-columns: 1fr; }
  .panel-heading { gap: 12px; }
  .fact-grid, .observation-facts, .detail-grid { grid-template-columns: 1fr; }
  .counter-grid { grid-template-columns: repeat(2, 1fr); }
  .observation-card { grid-template-columns: 38px minmax(0, 1fr); }
  .filter-bar { grid-template-columns: 1fr; }
  .search-control { grid-column: auto; }
  .table-row { grid-template-columns: 1fr; }
  .table-head { display: none; }
  footer { align-items: flex-start; flex-direction: column; }
}
@media (prefers-reduced-motion: reduce) { html { scroll-behavior: auto; } }
"#;

const SCRIPT: &str = r#"
(() => {
  "use strict";
  const root = document.documentElement;
  const panels = Array.from(document.querySelectorAll("[data-panel]"));
  const navButtons = Array.from(document.querySelectorAll("[data-panel-target]"));
  root.classList.add("enhanced");

  const activatePanel = (panelId) => {
    panels.forEach((panel) => { panel.hidden = panel.dataset.panel !== panelId; });
    navButtons.forEach((button) => {
      const active = button.dataset.panelTarget === panelId;
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-current", active ? "page" : "false");
    });
  };

  navButtons.forEach((button) => {
    button.addEventListener("click", () => activatePanel(button.dataset.panelTarget));
  });

  const themeButton = document.querySelector('[data-action="toggle-theme"]');
  themeButton.addEventListener("click", () => {
    const dark = root.dataset.theme !== "dark";
    root.dataset.theme = dark ? "dark" : "light";
    themeButton.textContent = dark ? "Light" : "Dark";
  });

  const densityButton = document.querySelector('[data-action="toggle-density"]');
  densityButton.addEventListener("click", () => {
    const compact = root.dataset.density !== "compact";
    root.dataset.density = compact ? "compact" : "comfortable";
    densityButton.textContent = compact ? "Comfortable" : "Compact";
  });

  const search = document.querySelector('[data-action="search-observations"]');
  const eventFilter = document.querySelector('[data-action="filter-event"]');
  const relationFilter = document.querySelector('[data-action="filter-relation"]');
  const clearFilters = document.querySelector('[data-action="clear-observation-filters"]');
  const filterStatus = document.querySelector("[data-filter-status]");
  const observations = Array.from(document.querySelectorAll("[data-observation]"));
  let identityFilter = "0";

  const applyObservationFilters = () => {
    const query = search.value.trim().toLocaleLowerCase();
    let visible = 0;
    observations.forEach((observation) => {
      const queryMatch = query === "" || observation.textContent.toLocaleLowerCase().includes(query);
      const eventMatch = eventFilter.value === "0" || observation.dataset.eventIndex === eventFilter.value;
      const relationMatch = relationFilter.value === "0" || observation.dataset.relationIndex === relationFilter.value;
      const identityMatch = identityFilter === "0" || observation.dataset.identityIndex === identityFilter;
      const show = queryMatch && eventMatch && relationMatch && identityMatch;
      observation.hidden = !show;
      if (show) visible += 1;
    });
    filterStatus.textContent = `${visible} of ${observations.length} observations shown`;
  };

  [search, eventFilter, relationFilter].forEach((control) => {
    control.addEventListener(control === search ? "input" : "change", applyObservationFilters);
  });
  clearFilters.addEventListener("click", () => {
    search.value = "";
    eventFilter.value = "0";
    relationFilter.value = "0";
    identityFilter = "0";
    applyObservationFilters();
  });

  document.querySelectorAll("[data-evidence-target]").forEach((button) => {
    button.addEventListener("click", () => {
      identityFilter = "0";
      search.value = "";
      eventFilter.value = "0";
      relationFilter.value = "0";
      applyObservationFilters();
      activatePanel("observations");
      const target = document.getElementById(button.dataset.evidenceTarget);
      if (target) {
        target.classList.add("is-targeted");
        target.scrollIntoView({ block: "center" });
        window.setTimeout(() => target.classList.remove("is-targeted"), 1800);
      }
    });
  });

  document.querySelectorAll("[data-identity-target]").forEach((button) => {
    button.addEventListener("click", () => {
      identityFilter = button.dataset.identityTarget;
      search.value = "";
      eventFilter.value = "0";
      relationFilter.value = "0";
      activatePanel("observations");
      applyObservationFilters();
    });
  });

  activatePanel(document.body.dataset.defaultPanel);
  applyObservationFilters();
})();
"#;
