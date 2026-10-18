// Three-way text merge. Never invents a resolution: either every change from
// both sides lands, or the caller gets {ok:false} and keeps a conflict copy.

import { diff3Merge } from "node-diff3";
import DiffMatchPatch from "diff-match-patch";

export type MergeResult = { ok: true; text: string; how: "trivial" | "diff3" | "dmp" } | { ok: false };

const lines = (s: string) => s.split(/(?<=\n)/);

export function merge3(base: string, local: string, remote: string): MergeResult {
  if (local === remote) return { ok: true, text: local, how: "trivial" };
  if (base === local) return { ok: true, text: remote, how: "trivial" };
  if (base === remote) return { ok: true, text: local, how: "trivial" };

  // 1. Line-level diff3: clean whenever the two sides touched different lines.
  //    Both sides only inserting at the same spot (two appends to a daily note)
  //    is not a real conflict: keep both, remote's first since it is already committed.
  const regions = diff3Merge(lines(local), lines(base), lines(remote), { excludeFalseConflicts: true });
  if (regions.every((r) => r.ok || r.conflict!.o.length === 0)) {
    const both = (b: string[], a: string[]) => (b.length && a.length && !b[b.length - 1].endsWith("\n") ? [...b, "\n", ...a] : [...b, ...a]);
    return { ok: true, text: regions.flatMap((r) => r.ok ?? both(r.conflict!.b, r.conflict!.a)).join(""), how: "diff3" };
  }

  // 2. Character-level: replay local's edits onto remote. Accept only if every
  //    patch lands, and the result still contains every line remote added and
  //    every line local added, so neither side's text can silently vanish.
  const dmp = new DiffMatchPatch();
  dmp.Match_Threshold = 0.25;
  dmp.Match_Distance = 1000;
  dmp.Patch_DeleteThreshold = 0.25;
  const patches = dmp.patch_make(base, local);
  const [text, applied] = dmp.patch_apply(patches, remote) as [string, boolean[]];
  if (applied.every(Boolean) && keepsAdditions(base, local, text) && keepsAdditions(base, remote, text) && keepsCommon(local, remote, text)) {
    return { ok: true, text, how: "dmp" };
  }
  return { ok: false };
}

/** A line both sides still have (as many times as both have it) must survive:
 *  fuzzy patching can otherwise land a deletion on the wrong line. */
function keepsCommon(local: string, remote: string, merged: string): boolean {
  const count = (s: string) => {
    const m = new Map<string, number>();
    for (const l of lines(s)) {
      const t = l.trimEnd();
      if (t.trim()) m.set(t, (m.get(t) ?? 0) + 1);
    }
    return m;
  };
  const lc = count(local), rc = count(remote), mc = count(merged);
  for (const [t, n] of lc) if ((mc.get(t) ?? 0) < Math.min(n, rc.get(t) ?? 0)) return false;
  return true;
}

/** Every non-blank line present in `side` but not in `base` must appear in `merged`. */
function keepsAdditions(base: string, side: string, merged: string): boolean {
  const baseSet = new Set(lines(base).map((l) => l.trimEnd()));
  const mergedText = merged;
  for (const l of lines(side)) {
    const t = l.trimEnd();
    if (t.trim() === "" || baseSet.has(t)) continue;
    if (!mergedText.includes(t)) return false;
  }
  return true;
}
