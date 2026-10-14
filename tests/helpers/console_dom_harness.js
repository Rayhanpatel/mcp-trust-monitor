"use strict";
// Minimal DOM for executing the unchanged shipped console app.js against a live,
// token-protected ConsoleServer. Adapted from the batch 2 review harness
// (console/drive_shipped_app.js). It is not a browser engine: it models only what the
// app uses (element registry from the shipped index.html, textContent, value, select
// options, hidden/disabled, listeners, timers and fetch). Like a browser, a click on a
// disabled control does nothing unless the test forces it, and same-origin POSTs carry
// the page Origin. Commands arrive as JSON lines on stdin; each reply is one JSON line.
const fs = require("fs"), path = require("path"), vm = require("vm"), readline = require("readline");
const [appPath, consoleUrl] = process.argv.slice(2);
const page = new URL(consoleUrl), origin = page.origin;
const html = fs.readFileSync(path.join(path.dirname(appPath), "index.html"), "utf8");

class Element {
  constructor(tag, id = "") {
    this.tagName = tag; this.id = id; this.children = []; this.listeners = {}; this._text = "";
    this._value = tag === "option" ? undefined : ""; this.hidden = false; this.disabled = false;
    this.className = ""; this.title = ""; this.dataset = {}; this.attributes = {}; this.open = false;
    this.selectedIndex = -1; this.classList = {toggle() {}};
  }
  get textContent() { return this.children.length ? this.children.map(child => child.textContent).join("") : this._text; }
  set textContent(value) { this.children = []; this._text = String(value); }
  append(...nodes) {
    this.children.push(...nodes);
    if(this.tagName === "select" && this.selectedIndex < 0 && this.options.length) this.selectedIndex = 0;
  }
  replaceChildren(...nodes) { this.children = []; this._text = ""; if(this.tagName === "select") this.selectedIndex = -1; this.append(...nodes); }
  get firstChild() { return this.children[0]; }
  get options() { return this.children.filter(child => child.tagName === "option"); }
  get value() {
    if(this.tagName === "select") { const option = this.options[this.selectedIndex]; return option ? option.value : ""; }
    if(this.tagName === "option") return this._value ?? this.textContent;
    return this._value;
  }
  set value(value) {
    if(this.tagName === "select") { this.selectedIndex = this.options.findIndex(option => option.value === String(value)); return; }
    this._value = String(value);
  }
  addEventListener(type, callback) { (this.listeners[type] ??= []).push(callback); }
  dispatch(type) {
    const event = {type, target: this, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }};
    for(const callback of this.listeners[type] ?? []) callback(event);
  }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  showModal() { this.open = true; }
  close() { this.open = false; }
}

// Every element with an ID in the shipped page, with its tag, hidden flag and static options.
const registry = new Map();
for(const match of html.matchAll(/<(\w+)([^>]*?)\sid="([^"]+)"([^>]*)>/g)) {
  const [, tag, before, id, after] = match, attributes = before + " " + after, node = new Element(tag.toLowerCase(), id);
  node.hidden = /\shidden(?=[\s>=]|$)/.test(" " + attributes);
  node.disabled = /\sdisabled(?=[\s>=]|$)/.test(" " + attributes);
  const value = attributes.match(/\svalue="([^"]*)"/); if(value && tag.toLowerCase() === "input") node._value = value[1];
  registry.set(id, node);
}
for(const match of html.matchAll(/<select[^>]*\sid="([^"]+)"[^>]*>([\s\S]*?)<\/select>/g)) {
  for(const option of match[2].matchAll(/<option value="([^"]*)">([^<]*)<\/option>/g)) {
    const node = new Element("option"); node.value = option[1]; node.textContent = option[2]; registry.get(match[1]).append(node);
  }
}

const timers = [], posts = [], errors = [];
let inflight = 0;
process.on("unhandledRejection", error => errors.push(String(error && error.stack || error)));
const document = {getElementById: id => registry.get(id) ?? null, createElement: tag => new Element(tag),
  querySelectorAll: () => [], hidden: false};
const context = vm.createContext({URLSearchParams, location: {hash: page.hash}, document, console,
  setInterval: callback => { timers.push(callback); return timers.length; }, prompt: () => null,
  fetch: async (target, options = {}) => {
    inflight += 1;
    try {
      const method = options.method || "GET", headers = {...options.headers};
      if(method !== "GET") headers.Origin = origin;  // A browser adds Origin to same-origin POSTs.
      const response = await fetch(new URL(target, origin), {method, headers, body: options.body});
      const body = await response.text();
      if(method === "POST") posts.push({payload: JSON.parse(options.body), status: response.status, body: JSON.parse(body)});
      const parse = vm.runInContext("JSON", context).parse;
      return {ok: response.ok, status: response.status, json: async () => parse(body)};
    } finally { inflight -= 1; }
  }});

async function settle() {
  for(let quiet = 0; quiet < 3;) { await new Promise(resolve => setTimeout(resolve, 15)); quiet = inflight === 0 ? quiet + 1 : 0; }
}
function view() {
  const result = {};
  for(const [id, node] of registry) {
    result[id] = {text: node.textContent, value: node.value, hidden: node.hidden, disabled: node.disabled};
    if(node.tagName === "select") result[id].options = node.options.map(option => option.value);
  }
  return result;
}
function element(id) { const node = registry.get(id); if(!node) throw new Error(`no element ${id} in the shipped page`); return node; }

async function run(command) {
  let fired = true;
  if(command.op === "start") vm.runInContext(fs.readFileSync(appPath, "utf8"), context, {filename: appPath});
  else if(command.op === "tick") for(const timer of timers) timer();
  else if(command.op === "click") {
    const node = element(command.id);
    fired = command.force || !node.disabled;
    if(fired) node.dispatch("click");
  } else if(command.op === "submit") {
    // The operator presses the form's submit button; a disabled button submits nothing.
    // A page whose submit button has no ID is treated as having an enabled button.
    const button = command.button && registry.get(command.button);
    fired = command.force || !(button && button.disabled);
    if(fired) element(command.form).dispatch("submit");
  } else if(command.op === "set") {
    // An operator can only choose an option the page offers.
    const node = element(command.id);
    fired = node.tagName !== "select" || node.options.some(option => option.value === String(command.value));
    if(fired) { node.value = command.value; node.dispatch("input"); node.dispatch("change"); }
  } else if(command.op !== "view") throw new Error(`unknown command ${command.op}`);
  await settle();
  const sent = posts.splice(0);
  return {ok: true, fired, posts: sent, errors: errors.splice(0), view: view()};
}

const lines = readline.createInterface({input: process.stdin});
let queue = Promise.resolve();
lines.on("line", line => {
  queue = queue.then(async () => {
    let reply;
    try { reply = await run(JSON.parse(line)); }
    catch(error) { reply = {ok: false, error: String(error && error.stack || error), errors: errors.splice(0)}; }
    process.stdout.write(JSON.stringify(reply) + "\n");
  });
});
lines.on("close", () => { queue.then(() => process.exit(0)); });
