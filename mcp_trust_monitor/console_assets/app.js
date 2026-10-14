"use strict";
const $ = id => document.getElementById(id);
const text = (id, value) => { $(id).textContent = value; };
const pretty = value => JSON.stringify(value, null, 2);
const tokenFromLink = new URLSearchParams(location.hash.slice(1)).get("token");
let token = tokenFromLink || "", csrf = "", state = null, selected = null, preview = null, busy = false;
// What the operator reviewed, per server: the only target of approve and restore. A
// refresh updates status but never replaces it; only "Review the current state" does.
const reviews = new Map();
// One verdict draft per server, pinned to one observation. Its observation, assessment,
// evidence and rationale change together or not at all.
const drafts = new Map();
const REVIEW_FIELDS = [["trust_state", "Trust state"], ["revision", "Revision"], ["generation", "Generation"],
  ["policy_binding", "Active policy"], ["launch_identity", "Launch identity"]];
const label = value => String(value || "unknown").replaceAll("_", " ");
const shown = value => value === null || value === undefined || value === "" ? "none" : String(value);
function el(tag, value, cls) { const node = document.createElement(tag); if(value !== undefined) node.textContent = value; if(cls) node.className = cls; return node; }
function notice(message, error=false) { text("notice", message); $("notice").className = error ? "error" : ""; $("notice").hidden = false; }
async function api(path, payload) {
  const headers = {Authorization: `Bearer ${token}`};
  const options = {headers, credentials: "omit", cache: "no-store"};
  if(payload) { options.method="POST"; headers["Content-Type"]="application/json"; headers["X-CSRF-Token"]=csrf; options.body=JSON.stringify(payload); }
  const response = await fetch(path, options), body = await response.json();
  if(!response.ok) throw new Error(`${body.error}: ${body.message || "The local session could not authorize this request."}`);
  return body.result;
}
async function refresh() {
  if(!token) return;
  try { state = await api("/api/state"); csrf=state.csrf_token; $("workspace").hidden=false; $("connect-form").hidden=true; if(!state.servers.some(s=>s.server_id===selected)) selected=state.servers[0]?.server_id; render(); }
  catch(error) { notice(error.message, true); }
}
function operator() { const actor=$("actor").value.trim(); if(!actor) notice("Enter an operator name before acting.",true); return actor; }
async function act(action, fields={}) {
  if(busy) return null;
  const actor=operator(); if(!actor) return null;
  busy=true;
  try { const result=await api("/api/action", {action,actor,...fields}); notice(`${label(action)} completed. Check the recorded state and evidence below.`); await refresh(); return result; }
  catch(error) { notice(error.message, true); return null; }
  finally { busy=false; }
}
async function read(action, fields={}) {
  const actor=operator(); if(!actor) return null;
  try { return await api("/api/action", {action,actor,...fields}); }
  catch(error) { notice(error.message, true); return null; }
}
function current() { return state?.servers.find(s=>s.server_id===selected); }
function empty(container, message) { container.replaceChildren(el("p", message, "empty")); }
function details(title, value) { const d=el("details"), p=el("pre",pretty(value)); d.append(el("summary",title),p); return d; }
function fillSelect(id, items, valueKey, describe) {
  const node=$(id), previous=node.value;
  node.replaceChildren(el("option","Choose a record")); node.firstChild.value="";
  for(const item of items) { const option=el("option",describe(item)); option.value=item[valueKey]; node.append(option); }
  if([...node.options].some(o=>o.value===previous)) node.value=previous;
}
function reviewOf(server) {
  return Object.freeze({server_id: server.server_id, trust_state: server.state || "not_observed",
    revision: server.observed_revision ?? null, generation: server.generation ?? null,
    policy_binding: state.policy_binding ?? null, launch_identity: server.launch_identity ?? null,
    observed_tools: server.observed_tools || [], before_tools: server.before_tools || []});
}
function reviewChanges(review, server) {
  const now = reviewOf(server);
  return REVIEW_FIELDS.filter(([key]) => review[key] !== now[key])
    .map(([key, name]) => `${name}: reviewed ${shown(review[key])}; now ${shown(now[key])}`);
}
function render() {
  text("server-count",state.servers.length);
  $("servers").replaceChildren();
  for(const server of state.servers) { const b=el("button",undefined,server.server_id===selected?"active":""); b.append(el("span",server.server_id),el("small",label(server.state))); b.addEventListener("click",()=>{selected=server.server_id;render();}); $("servers").append(b); }
  const server=current(); text("server-name",selected || "No configured servers"); text("server-subtitle",server?.origin==="synthetic_fixture"?"Synthetic fixture · controlled demonstration data":"Configured local stdio server");
  // The first view of a server is its review; later changes need an explicit re-review.
  if(server && !reviews.has(server.server_id)) reviews.set(server.server_id, reviewOf(server));
  const review=server ? reviews.get(server.server_id) : null, changes=review ? reviewChanges(review, server) : [];
  text("trust-state",label(server?.state||"not observed")); $("trust-state").className="badge "+(server?.state||"");
  text("revision",server?.observed_revision || "—"); $("revision").title=server?.observed_revision||"";
  text("generation",server?.generation ?? "—"); text("catalog-count",server?.catalog?.length ?? 0);
  text("pending-count",state.audit?.pending ?? state.audit?.pending_count ?? "unavailable");
  text("origin",server?.origin || "origin not recorded");
  text("review-state",label(review?.trust_state || "not observed")); text("review-revision",review?.revision || "—");
  text("review-generation",review?.generation ?? "—"); text("review-policy",review?.policy_binding || "—");
  text("review-launch",review?.launch_identity || "—");
  $("review-stale").hidden=!changes.length; text("review-changes",changes.join("\n"));
  text("current-after",server?.observed_tools?.length?pretty(server.observed_tools):"No successful observation.");
  const observation=server?.latest_observation;
  text("last-observation",observation?`Last successful observation: ${observation.ts || "time unavailable"}`:"No successful observation recorded.");
  text("health",pretty(state.monitor_health || {catalog_error:server?.catalog_error||null,observation_failed_at:server?.observation_failed_at||null}));
  text("before",review?.before_tools?.length?pretty(review.before_tools):"No previously approved metadata.");
  text("after",review?.observed_tools?.length?pretty(review.observed_tools):"No successful observation.");
  $("observe").disabled=!server; $("review-once").disabled=!server?.observed_revision;
  $("review-current").disabled=!changes.length;
  $("approve").disabled=!review?.revision || changes.length>0 || ["quarantined","approved"].includes(review.trust_state);
  $("restore").disabled=!review?.revision || changes.length>0 || review.trust_state!=="quarantined";
  const catalog=$("catalog"); catalog.replaceChildren();
  if(!server?.catalog?.length) empty(catalog,server?.catalog_error?`Discovery unavailable: ${server.catalog_error}`:"No approved tools are currently available.");
  for(const entry of server?.catalog||[]) { const item=el("div",undefined,"entry"); item.append(el("h3",entry.definition?.name||"Tool"),el("p",entry.definition?.description||"No description"),details("Definition and selection token",entry)); catalog.append(item); }
  text("policy",pretty(state.policy)); text("audit",pretty(state.audit));
  const events=state.events.filter(e=>!selected||e.server_id===selected); text("event-count",`${events.length} shown · ${state.event_count} total`);
  const timeline=$("events"); timeline.replaceChildren();
  if(!events.length) empty(timeline,"No events recorded for this server.");
  for(const event of [...events].reverse()) { const item=el("div",undefined,"entry"), head=el("div",undefined,"entry-heading"); head.append(el("h3",label(event.event_type)),el("small",event.ts||"")); item.append(head,el("p",`Actor: ${event.actor || "unrecorded"} · ${event.origin || "origin unrecorded"} · ${event.event_id || "no ID"}`),details("Policy, precedent, recommendation and action evidence",event)); timeline.append(item); }
  $("memory-unavailable").hidden=state.memory.available; $("memory-configured").hidden=!state.memory.available;
  if(state.memory.available) renderMemory(server);
}
function newDraft(serverId, context) {
  return {server_id: serverId, observation: context.observation, assessments: context.assessments || [],
    assessment_event_id: "", value: "uncertain", rationale: "", supersedes: "", kept_over: null};
}
function activeDraft() { return selected ? drafts.get(selected) : undefined; }
function renderDraft(server) {
  const latest=server?.latest_verdict_context || null;
  let draft=server ? drafts.get(server.server_id) : undefined;
  if(server && !draft && latest) { draft=newDraft(server.server_id, latest); drafts.set(server.server_id, draft); }
  const sameObservation=draft && latest && latest.observation.observation_id===draft.observation.observation_id;
  // New assessments of the same observation may join the choices; nothing else changes.
  if(sameObservation) draft.assessments=latest.assessments || [];
  const newer=Boolean(draft && latest && !sameObservation), undecided=newer && draft.kept_over!==latest.observation.observation_id;
  $("draft-newer").hidden=!undecided; $("draft-kept").hidden=!newer || undecided;
  $("draft-empty").hidden=Boolean(draft); $("verdict-form").hidden=!draft;
  const observation=draft?.observation;
  text("observation-id",observation?.observation_id || "—"); text("draft-revision",observation?.revision || "—");
  text("draft-generation",observation?.generation ?? "—"); text("draft-observed-at",observation?.ts || "—");
  text("draft-tools",observation?pretty(observation.reviewed_tools || []):"");
  const assessments=draft?.assessments || [];
  fillSelect("assessment-event",assessments,"event_id",e=>`${label(e.event_type)} · ${e.ts || "time unavailable"} · ${e.event_id}`);
  const chosen=assessments.find(e=>e.event_id===draft?.assessment_event_id);
  $("assessment-event").value=chosen ? chosen.event_id : "";
  $("draft-unbound").hidden=!draft?.assessment_event_id || Boolean(chosen);
  text("draft-evidence",chosen?pretty(chosen):"Choose an assessment to see its recorded evidence.");
  for(const [id,key] of [["verdict-value","value"],["verdict-rationale","rationale"],["supersedes","supersedes"]]) if(draft && $(id).value!==draft[key]) $(id).value=draft[key];
  $("record-verdict").disabled=!draft || undecided || !chosen;
}
function renderMemory(server) {
  renderDraft(server);
  const verdicts=state.memory.verdicts, lessons=state.memory.lessons;
  fillSelect("lesson-verdict",verdicts.filter(v=>v.active!==false&&v.value!=="uncertain"),"verdict_id",v=>`${label(v.value)} · ${v.verdict_id}`);
  const registry=$("lessons"); registry.replaceChildren(); if(!lessons.length) empty(registry,"No lessons recorded. Start with an explicit correctness verdict.");
  for(const lesson of lessons) { const id=lesson.lesson_id, item=el("div",undefined,"entry"),head=el("div",undefined,"entry-heading"); head.append(el("h3",`${id} · version ${lesson.version}`),el("span",label(lesson.state),"badge")); item.append(head,el("p",`Policy: ${lesson.policy_binding} · Scope: ${lesson.scope}`),details("Lesson content, provenance and publication state",lesson));
    const buttons=el("div",undefined,"toolbar");
    const previewButton=el("button","Preview exact content"); previewButton.addEventListener("click",async()=>{const result=await act("preview_lesson",{lesson_id:id}); if(!result)return; preview=result;text("preview-body",result.body);text("preview-digest",result.digest);$("approve-lesson").disabled=result.state!=="draft";$("lesson-preview").showModal();});buttons.append(previewButton);
    const publish=el("button","Publish privately");publish.disabled=!state.memory.publication_available || !["approved","uploaded_unverified"].includes(lesson.state);publish.addEventListener("click",()=>act("publish_lesson",{lesson_id:id}));buttons.append(publish);
    const revoke=el("button","Revoke","danger");revoke.disabled=["revoked","rejected"].includes(lesson.state);revoke.addEventListener("click",()=>{const reason=prompt("Reason for revoking this lesson:");if(reason?.trim())act("revoke_lesson",{lesson_id:id,reason});});buttons.append(revoke);item.append(buttons);registry.append(item);
  }
  const history=$("verdicts"); history.replaceChildren();if(!verdicts.length)empty(history,"No operator correctness verdicts recorded.");
  for(const verdict of [...verdicts].reverse()) { const item=el("div",undefined,"entry");item.append(el("h3",`${label(verdict.value)} · ${verdict.verdict_id}`),el("p",verdict.rationale),details("Provenance and supersession",verdict));history.append(item); }
}
async function loadDraft(serverId, observationId) {
  const context=await read("verdict_context",{observation_id:observationId});
  if(!context) return null;
  if(context.observation.server_id!==serverId) { notice("That observation belongs to another server. Select that server first.",true); return null; }
  return context;
}
$("refresh").addEventListener("click",refresh);
$("connect-form").addEventListener("submit",event=>{event.preventDefault();token=$("local-token").value;refresh();});
for(const button of document.querySelectorAll("[data-tab]")) button.addEventListener("click",()=>{for(const tab of document.querySelectorAll("[data-tab]")){const active=tab===button;tab.classList.toggle("active",active);tab.setAttribute("aria-selected",String(active));$("tab-"+tab.dataset.tab).hidden=!active;}});
$("observe").addEventListener("click",()=>act("observe",{server_id:selected}));
$("review-once").addEventListener("click",()=>act("review",{server_id:selected}));
$("review-current").addEventListener("click",()=>{const server=current(); if(!server) return; reviews.set(server.server_id, reviewOf(server)); notice("Approve and restore now target the state shown below. Review it before acting."); render();});
for(const action of ["approve","restore"]) $(action).addEventListener("click",()=>{
  const server=current(), review=server ? reviews.get(server.server_id) : null;
  if(!review || reviewChanges(review, server).length) { notice("The current state differs from the state you reviewed. Review the current state before acting.",true); render(); return; }
  act(action,{server_id:review.server_id,revision:review.revision,generation:review.generation,policy_binding:review.policy_binding,launch_identity:review.launch_identity});
});
$("quarantine-form").addEventListener("submit",event=>{event.preventDefault();act("quarantine",{server_id:selected,reason:$("quarantine-reason").value});});
$("start-monitor").addEventListener("click",()=>act("start_monitor"));$("stop-monitor").addEventListener("click",()=>act("stop_monitor"));
$("assessment-event").addEventListener("change",()=>{const draft=activeDraft(); if(draft) { draft.assessment_event_id=$("assessment-event").value; renderDraft(current()); }});
for(const [id,key] of [["verdict-value","value"],["verdict-rationale","rationale"],["supersedes","supersedes"]]) for(const type of ["input","change"]) $(id).addEventListener(type,()=>{const draft=activeDraft(); if(draft) draft[key]=$(id).value;});
$("keep-draft").addEventListener("click",async()=>{
  const draft=activeDraft(), latest=current()?.latest_verdict_context; if(!draft || !latest) return;
  const context=await loadDraft(draft.server_id, draft.observation.observation_id);
  if(!context || drafts.get(draft.server_id)!==draft) return;
  draft.assessments=context.assessments || []; draft.kept_over=latest.observation.observation_id; renderDraft(current());
});
$("replace-draft").addEventListener("click",()=>{const server=current(); if(!server?.latest_verdict_context) return; drafts.set(server.server_id, newDraft(server.server_id, server.latest_verdict_context)); renderDraft(server);});
$("load-observation").addEventListener("click",async()=>{
  const serverId=selected, observationId=$("load-observation-id").value.trim(); if(!serverId || !observationId) return;
  const context=await loadDraft(serverId, observationId); if(!context) return;
  const draft=newDraft(serverId, context); const latest=current()?.latest_verdict_context;
  if(latest && latest.observation.observation_id!==observationId) draft.kept_over=latest.observation.observation_id;
  drafts.set(serverId, draft); $("load-observation-id").value=""; renderDraft(current());
});
$("verdict-form").addEventListener("submit",async event=>{
  event.preventDefault();
  const draft=activeDraft(); if(!draft || $("record-verdict").disabled) return;
  const result=await act("record_verdict",{observation_id:draft.observation.observation_id,assessment_event_id:draft.assessment_event_id,value:draft.value,rationale:draft.rationale,supersedes:draft.supersedes});
  if(result && drafts.get(draft.server_id)===draft) { drafts.delete(draft.server_id); if(state) render(); }
});
$("lesson-form").addEventListener("submit",event=>{event.preventDefault();act("draft_lesson",{verdict_id:$("lesson-verdict").value,summary:$("lesson-summary").value,rule_ids:$("lesson-rules").value.split(",").map(x=>x.trim()).filter(Boolean),family:$("lesson-family").value});});
$("close-preview").addEventListener("click",()=>$("lesson-preview").close());
$("approve-lesson").addEventListener("click",async()=>{if(!preview)return;const result=await act("approve_lesson",{lesson_id:preview.lesson_id,digest:preview.digest});if(result)$("lesson-preview").close();});
if(token) refresh(); else $("connect-form").hidden=false;
setInterval(()=>{if(token&&!busy&&!document.hidden)refresh();},5000);
