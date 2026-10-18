import { describe, expect, it } from "vitest";
import { merge3 } from "../src/core/merge";

describe("merge3", () => {
  const base = "# Title\n\nline one\nline two\nline three\n";

  it("takes the only side that changed", () => {
    expect(merge3(base, base + "x\n", base)).toMatchObject({ ok: true, text: base + "x\n" });
    expect(merge3(base, base, base + "y\n")).toMatchObject({ ok: true, text: base + "y\n" });
  });

  it("merges edits on different lines (diff3)", () => {
    const local = base.replace("line one", "line ONE");
    const remote = base.replace("line three", "line THREE");
    const m = merge3(base, local, remote);
    expect(m).toMatchObject({ ok: true, how: "diff3" });
    if (m.ok) expect(m.text).toBe("# Title\n\nline ONE\nline two\nline THREE\n");
  });

  it("keeps both appends at the end of a daily note", () => {
    const m = merge3(base, base + "- from mac\n", base + "- from iphone\n");
    expect(m.ok).toBe(true);
    if (m.ok) {
      expect(m.text).toContain("- from mac");
      expect(m.text).toContain("- from iphone");
      expect(m.text.startsWith(base)).toBe(true);
    }
  });

  it("merges two edits within one paragraph line-block when they don't overlap", () => {
    const b = "alpha beta gamma delta epsilon zeta eta theta iota kappa\n";
    const l = "ALPHA beta gamma delta epsilon zeta eta theta iota kappa\n";
    const r = "alpha beta gamma delta epsilon zeta eta theta iota KAPPA\n";
    const m = merge3(b, l, r);
    // same line edited on both sides: only accept if both edits survive
    if (m.ok) {
      expect(m.text).toContain("ALPHA");
      expect(m.text).toContain("KAPPA");
    }
  });

  it("refuses a true conflict instead of picking a side", () => {
    const local = base.replace("line two", "line two (mac)");
    const remote = base.replace("line two", "line two (iphone)");
    expect(merge3(base, local, remote)).toEqual({ ok: false });
  });

  it("identical changes on both sides are clean", () => {
    const both = base.replace("line two", "LINE TWO");
    expect(merge3(base, both, both)).toMatchObject({ ok: true, text: both });
  });

  // Found by the simulator (seed 6939): local rewrote a line remote had deleted;
  // fuzzy patching landed the rewrite on a similar-looking line and erased it.
  it("never lets a fuzzy patch overwrite a line both sides kept", () => {
    const base = "- t6939x7 rewritten\n\n- t6939x1 first\n- t6939x3 rewritten\n- t6939x8 note";
    const local = "- t6939x11 rewritten\n\n- t6939x1 first\n- t6939x3 rewritten\n- t6939x8 note";
    const remote = "- t6939x1 first\n- t6939x10 note\n- t6939x9 note\n- t6939x3 rewritten\n- t6939x8 note";
    const m = merge3(base, local, remote);
    if (m.ok) for (const t of ["x1 ", "x3 ", "x8 ", "x9 ", "x10 ", "x11 "]) expect(m.text).toContain(`t6939${t}`);
  });

  it("delete vs edit of the same line is a conflict", () => {
    const local = base.replace("line two\n", "");
    const remote = base.replace("line two", "line two edited");
    expect(merge3(base, local, remote).ok).toBe(false);
  });
});
