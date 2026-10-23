// #1123 D-hub: the hub web checks the question hash itself (frozen core fixtures, tests/data/core_f1), shows the selected
// option in the sign prompt, and never signs an option it has not verified.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, questionRenderable, verifyQuestion } from "../../src/orch_hub/web/render.js";

const FORMS = JSON.parse(readFileSync(new URL("../data/core_f1/questions.json", import.meta.url))).forms;
const HASHES = JSON.parse(readFileSync(new URL("../data/core_f1/hashes.json", import.meta.url)));
const form = (n) => FORMS.find((f) => f.name === n);
const clone = (x) => JSON.parse(JSON.stringify(x));
const needs = (f) => ({ item: f.hub_needs.row, content: f.hub_needs.content });

test("the hash is recomputed in the browser for every fixture form and matches core", async () => {
  for (const f of FORMS) {
    const { item, content } = needs(f);
    const qv = await verifyQuestion(item, content);
    assert.ok(qv, f.name);
    assert.equal(qv.hash, f.raw_event.hash);
  }
});

test("a changed byte anywhere, or an unknown part, makes the question unverifiable", async () => {
  const f = form("choice_full");
  const muts = [
    (c) => (c.text += "!"), (c) => (c.spec.why = "x"), (c) => delete c.spec.details, (c) => (c.spec.recommended = "api"),
    (c) => delete c.spec.allow_other, (c) => (c.options[0].label = "Monthly CSV."), (c) => c.options.reverse(),
    (c) => c.options[0].facts.reverse(), (c) => delete c.options[1].text, (c) => (c.spec.kind = "text"),
    (c) => (c.spec.future = "x"), (c) => (c.options[0].preview = "p"), (c) => (c.options[0].facts = [{ label: "a", value: "b" }]),
    (c) => (c.unverifiable = true), (c) => delete c.spec, (c) => delete c.options,
  ];
  for (const [i, m] of muts.entries()) {
    const c = clone(f.hub_needs.content);
    m(c);
    assert.equal(await verifyQuestion(f.hub_needs.row, c), null, "mutation " + i);
  }
  const row = { ...f.hub_needs.row, hash: "sha256:" + "00".repeat(32) };
  assert.equal(await verifyQuestion(row, f.hub_needs.content), null);
  assert.equal(await verifyQuestion({ ...f.hub_needs.row, log: "01J9ZK4Q7M3R8T2V6X0B5N1C9E" }, f.hub_needs.content), null);
});

test("the old label-only question has no spec: not verifiable, not renderable", async () => {
  const c = { question: "Q1", text: "Ok?", options: [{ key: "a", label: "A" }, { key: "b", label: "B" }] };
  assert.equal(await verifyQuestion({ item_id: "x", log: "y", hash: "sha256:" + "0".repeat(64) }, c), null);
  assert.equal(questionRenderable("Ok?", c.options, undefined), false);
});

test("core's refused shapes this page can see are not renderable", () => {
  for (const v of HASHES.question_hash_refused) {
    const q = v.question;
    if (!q || typeof q !== "object") continue;
    if (["legacy_shape_without_kind", "kind_null", "kind_unknown", "unknown_question_key", "unknown_option_key", "choice_one_option", "choice_seven_options", "text_with_options", "allow_other_false", "recommended_not_a_key", "facts_object_form", "facts_four", "key_duplicate"].includes(v.name)) {
      const { id, to, blocking, text, options, ...spec } = q;
      assert.equal(questionRenderable(text, options, spec), false, v.name);
    }
  }
});

function ctxFor(ev) {
  return { contract: 1, suite: 2, workspace_id: "aa".repeat(16), log: "01J9ZK4Q7M3R8T2V6X0B5N1C9D", event: { auth: "hub", type: "question.answered", question: "Q1", ...ev } };
}
const D = new Uint8Array(32);

test("the prompt shows the selected option (title, meaning, facts, cost, question, details) before signing", async () => {
  const f = form("choice_full");
  const qv = await verifyQuestion(f.hub_needs.row, f.hub_needs.content);
  const d = describe(ctxFor({ hash: qv.hash, option: "csv" }), D, null, qv);
  assert.equal(d.signable, true);
  assert.match(d.sentence, /with “Monthly CSV”/);
  const rows = Object.fromEntries(d.facts);
  assert.equal(d.facts[0][0], "You chose");
  assert.equal(rows["You chose"], "Monthly CSV");
  assert.equal(rows["What it means"], "One file a month, checked by hand");
  assert.equal(rows.Effort, "½ day");
  assert.equal(rows.Cost, "½ day");
  assert.equal(rows.Question, f.raw_event.question.text);
  assert.match(rows.Details, /we import monthly/);
});

test("an option answer is unsignable without the verified question that lists it", async () => {
  const f = form("choice_full");
  const qv = await verifyQuestion(f.hub_needs.row, f.hub_needs.content);
  assert.equal(describe(ctxFor({ hash: qv.hash, option: "csv" }), D).signable, false, "no question at all");
  assert.equal(describe(ctxFor({ hash: qv.hash, option: "zzz" }), D, null, qv).signable, false, "option not listed");
  assert.equal(describe(ctxFor({ hash: "sha256:" + "11".repeat(32), option: "csv" }), D, null, qv).signable, false, "other hash");
  assert.equal(describe(ctxFor({ hash: qv.hash, option: "csv", smuggled: 1 }), D, null, qv).signable, false);
});

test("the prompt escapes hidden characters in the shown option", async () => {
  const f = form("choice_full");
  const c = clone(f.hub_needs.content);
  c.options[0].label = "Pay‮out";
  const row = { ...f.hub_needs.row, hash: "x" };
  // not the fixture hash: build the verified object by hand to test display escaping alone
  const qv = { text: c.text, options: c.options, spec: c.spec, hash: row.hash };
  const d = describe(ctxFor({ hash: "x", option: "csv" }), D, null, qv);
  assert.match(d.sentence, /Pay<U\+202E>out/);
});
