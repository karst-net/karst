// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// A schema-aware editor for the access policy document (issue #128).
//
// Two lint layers, deliberately kept separate:
//   - JSON syntax errors, from `jsonParseLinter()`, live and free — every
//     keystroke, no network round trip.
//   - The server's own semantic diagnostics (an undefined group, a bad port
//     range), applied only when the caller passes a new `diagnostics` array —
//     that is still a real request to /policy/validate, and this component
//     does not decide when to make one.
//
// Autocomplete is schema-shaped rather than schema-driven in the generic JSON
// Schema sense: `schema` names the four top-level keys and each rule's three
// fields, and this walks the JSON syntax tree to offer the right set for
// where the cursor actually is, rather than implementing a general-purpose
// JSON Schema completion engine for a four-key format that will not grow one
// key a year.
import { useEffect, useRef } from "react";
import { autocompletion, type CompletionContext, type CompletionResult } from "@codemirror/autocomplete";
import { json, jsonParseLinter } from "@codemirror/lang-json";
import { HighlightStyle, syntaxHighlighting, syntaxTree } from "@codemirror/language";
import { Diagnostic, linter, setDiagnostics } from "@codemirror/lint";
import { EditorState } from "@codemirror/state";
import { EditorView, basicSetup } from "codemirror";
import { tags } from "@lezer/highlight";

// CodeMirror's own default highlight style is a fixed, light-mode-oriented
// palette — on the app's dark surface it rendered strings at a 2.38:1
// contrast ratio against a 4.5:1 WCAG AA requirement (found by this app's own
// axe sweep). Every color here is one of the app's existing design tokens
// rather than a new one: they are already chosen to hold contrast against
// `--surface` in both themes, and `var(...)` means this repaints itself when
// the theme toggles without this component doing anything.
const editorTheme = EditorView.theme({
  "&": { color: "var(--text)", backgroundColor: "var(--surface)" },
  ".cm-content": { caretColor: "var(--text)" },
  ".cm-gutters": { backgroundColor: "var(--surface-raised)", color: "var(--muted)", border: "none" },
  ".cm-activeLine": { backgroundColor: "var(--surface-raised)" },
  ".cm-activeLineGutter": { backgroundColor: "var(--surface-raised)" },
  "&.cm-focused": { outline: "2px solid var(--focus)" },
});
const editorHighlight = syntaxHighlighting(HighlightStyle.define([
  { tag: tags.propertyName, color: "var(--accent)" },
  { tag: tags.string, color: "var(--text)" },
  { tag: [tags.number, tags.bool, tags.null], color: "var(--warning)" },
  { tag: [tags.brace, tags.bracket, tags.punctuation], color: "var(--muted)" },
]));

export type PolicyDiagnostic = { severity: string; message: string; line: number; column: number };

/** The shape this cares about from GET /policy/schema — a JSON Schema
 * (2020-12) document. Everything else in it (descriptions, patterns) is for
 * a human or a generic schema tool, not this hand-rolled completion source. */
export type PolicySchema = {
  properties?: Record<string, { const?: string; items?: { properties?: Record<string, unknown> } }>;
};

// Used until the schema has loaded (or if it fails to) — the same four keys
// and three rule fields Document has always had, so the editor is never
// worse than before this endpoint existed.
const fallbackTopLevelKeys = ["groups", "tagOwners", "acls", "ssh"];
const fallbackRuleKeys = ["action", "src", "dst"];
const fallbackActionValue = "accept";

function topLevelKeysOf(schema: PolicySchema | undefined): string[] {
  const keys = schema?.properties && Object.keys(schema.properties);
  return keys?.length ? keys : fallbackTopLevelKeys;
}

function ruleKeysOf(schema: PolicySchema | undefined): string[] {
  const properties = schema?.properties?.acls?.items?.properties;
  const keys = properties && Object.keys(properties);
  return keys?.length ? keys : fallbackRuleKeys;
}

function actionValueOf(schema: PolicySchema | undefined): string {
  return schema?.properties?.acls?.items?.properties?.action &&
    typeof (schema.properties.acls.items.properties.action as { const?: unknown }).const === "string"
    ? ((schema.properties.acls.items.properties.action as { const: string }).const)
    : fallbackActionValue;
}

/** Every "group:x" / "tag:x" key already defined in the document, found by
 * scanning rather than parsing — the document the user is mid-typing is
 * often not valid JSON, and a scan degrades gracefully where a parse would
 * offer nothing at all. */
function definedSelectors(doc: string): string[] {
  const matches = doc.matchAll(/"((?:group|tag):[^"\\]*)"\s*:/g);
  return [...new Set([...matches].map((m) => m[1]))];
}

/** Where in the JSON structure the cursor sits, walked from the syntax tree
 * rather than guessed from surrounding text — indentation and whitespace
 * inside a JSON document carry no meaning, so a text heuristic would be
 * guessing at exactly the positions a real editor gets used for.
 *
 * `schemaRef` rather than a closed-over value: the schema arrives from the
 * network after the editor (and this completion source) is constructed, and
 * CodeMirror extensions are fixed at construction time. */
function createPolicyCompletions(schemaRef: { current: PolicySchema | undefined }) {
  return (context: CompletionContext): CompletionResult | null => {
    const word = context.matchBefore(/"[^"]*/);
    if (!word) return null;
    const tree = syntaxTree(context.state);
    const node = tree.resolveInner(word.from, 1);
    const insideArrayNamed = (name: string): boolean => {
      // PropertyName -> Property -> Object -> Array -> Property(name)
      let n = node.node;
      while (n.name !== "Array" && n.parent) n = n.parent;
      if (n.name !== "Array" || !n.parent || n.parent.name !== "Property") return false;
      const key = n.parent.firstChild;
      return key !== null && context.state.sliceDoc(key.from, key.to) === `"${name}"`;
    };

    if (node.name === "PropertyName") {
      // A key being typed. Root object -> top-level keys; a rule object one
      // level under "acls"/"ssh" -> action/src/dst.
      const object = node.parent;
      const grandparent = object?.parent;
      if (object?.name === "Object" && (grandparent === null || grandparent?.name === "JsonText")) {
        return { from: word.from, options: topLevelKeysOf(schemaRef.current).map((label) => ({ label: `"${label}"`, type: "property" })) };
      }
      if (object?.name === "Object" && grandparent?.name === "Array" && (insideArrayNamed("acls") || insideArrayNamed("ssh"))) {
        return { from: word.from, options: ruleKeysOf(schemaRef.current).map((label) => ({ label: `"${label}"`, type: "property" })) };
      }
      return null;
    }

    if (node.name === "String" && node.parent?.name === "Property") {
      const key = node.parent.firstChild;
      const keyText = key ? context.state.sliceDoc(key.from, key.to) : "";
      if (keyText === `"action"`) {
        return { from: word.from, options: [{ label: `"${actionValueOf(schemaRef.current)}"`, type: "constant" }] };
      }
      if (keyText === `"src"` || keyText === `"dst"`) {
        const options = [{ label: `"*"`, type: "constant" }, ...definedSelectors(context.state.doc.toString()).map((s) => ({ label: `"${s}"`, type: "variable" }))];
        return { from: word.from, options };
      }
    }
    return null;
  };
}

/** A schema-aware JSON editor. Uncontrolled after mount: `value` seeds the
 * initial document and is re-applied only when it changes to a value the
 * editor does not already hold (loading a different policy version),
 * because re-syncing on every keystroke would fight the user's own cursor. */
export function PolicyEditor({ value, onChange, diagnostics, schema, labelledBy, describedBy }: {
  value: string;
  onChange: (value: string) => void;
  diagnostics: PolicyDiagnostic[];
  /** From GET /policy/schema. `undefined` until it loads; completions fall
   * back to Document's known shape until then, so the editor works either way. */
  schema: PolicySchema | undefined;
  /** id of the visible element that labels this editor, e.g. a <label>. */
  labelledBy: string;
  /** id of the visible element that describes it, e.g. help text. */
  describedBy?: string;
}) {
  const container = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView>(undefined);
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;
  const schemaRef = useRef(schema);
  schemaRef.current = schema;

  useEffect(() => {
    if (!container.current) return;
    const state = EditorState.create({
      doc: value,
      extensions: [
        basicSetup,
        json(),
        editorTheme,
        editorHighlight,
        linter(jsonParseLinter()),
        autocompletion({ override: [createPolicyCompletions(schemaRef)] }),
        // CodeMirror's own content element already carries role="textbox"
        // and aria-multiline; a wrapping element with the same role would
        // nest two textboxes, which is invalid rather than merely redundant.
        // This is the correct place for the label and description.
        EditorView.contentAttributes.of({
          "aria-labelledby": labelledBy,
          ...(describedBy ? { "aria-describedby": describedBy } : {}),
        }),
        EditorView.updateListener.of((update) => {
          if (update.docChanged) onChangeRef.current(update.state.doc.toString());
        }),
      ],
    });
    const created = new EditorView({ state, parent: container.current });
    view.current = created;
    return () => { created.destroy(); view.current = undefined; };
    // Intentionally mount-once: the editor owns its document after creation,
    // and `value` below is applied through the explicit sync effect instead.
  }, []);

  useEffect(() => {
    const current = view.current;
    if (!current || current.state.doc.toString() === value) return;
    current.dispatch({ changes: { from: 0, to: current.state.doc.length, insert: value } });
  }, [value]);

  useEffect(() => {
    const current = view.current;
    if (!current) return;
    const mapped: Diagnostic[] = diagnostics.map((d) => {
      const clampedLine = Math.min(Math.max(d.line, 1), current.state.doc.lines);
      const line = current.state.doc.line(clampedLine);
      const from = Math.min(line.from + Math.max(d.column - 1, 0), line.to);
      return { from, to: from, severity: d.severity === "error" ? "error" : "warning", message: d.message };
    });
    current.dispatch(setDiagnostics(current.state, mapped));
  }, [diagnostics]);

  return <div ref={container} />;
}
