// Small helpers shared by the engine, the Obsidian adapter and the simulator.

export const utf8 = new TextEncoder();
export const utf8d = new TextDecoder("utf-8", { fatal: false });

export function toB64(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s);
}

export function fromB64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function toHex(b: ArrayBuffer | Uint8Array): string {
  const u = b instanceof Uint8Array ? b : new Uint8Array(b);
  let s = "";
  for (const x of u) s += x.toString(16).padStart(2, "0");
  return s;
}

export function bytesEqual(a: Uint8Array | null, b: Uint8Array | null): boolean {
  if (a === null || b === null) return a === b;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function uuid4(): string {
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = toHex(b);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** Paths are compared in NFC: macOS can hand back NFD names for the same file. */
export function normPath(p: string): string {
  return p.normalize("NFC");
}

const TEXT_EXT = new Set(["md", "markdown", "txt"]);

/** Files we three-way merge. Everything else is "remote wins, local becomes a conflict copy". */
export function isMergeable(path: string): boolean {
  const dot = path.lastIndexOf(".");
  return dot > path.lastIndexOf("/") && TEXT_EXT.has(path.slice(dot + 1).toLowerCase());
}

/** A name as a forgiving filesystem may resolve it: case-folded (macOS, iOS and
 *  Windows; upper-then-lower also catches "ſ" and the Kelvin sign) and without
 *  the trailing dots/spaces Windows drops. Over-matching here only skips a file. */
function fold(name: string): string {
  return name.normalize("NFKC").toUpperCase().toLowerCase().replace(/[. ]+$/, "");
}

/** v1 syncs vault content only: never .obsidian, trash, or OS litter. */
export function isExcluded(path: string, configDir = ".obsidian"): boolean {
  const first = fold(path.split("/")[0]);
  if (first === fold(configDir) || first === ".trash" || first === ".git") return true;
  const base = path.slice(path.lastIndexOf("/") + 1);
  return base === ".DS_Store" || base.startsWith("._") || base === "Thumbs.db";
}

/** A path another device sent us is only ever written if it is a plain relative
 *  vault path outside the excluded areas: no "..", absolute or empty segments,
 *  backslashes, colons, control characters or trailing dots/spaces, and never
 *  into the config folder under any spelling the filesystem would accept. */
export function isSafeRemotePath(path: string, configDir = ".obsidian"): boolean {
  if (!path || path.length > 1024 || /[\\\x00-\x1f\x7f]/.test(path) || path.startsWith("/")) return false;
  // trailing dot/space and ":" (Windows streams) let two names reach the same file
  if (path.split("/").some((seg) => seg === "" || seg === "." || seg === ".." || /[. ]$/.test(seg) || seg.includes(":"))) return false;
  return !isExcluded(path, configDir);
}

/** "dir/Note.md" -> "dir/Note (conflict MBP 2026-10-18 1432).md" */
export function conflictName(path: string, device: string, now: Date, n = 0): string {
  const slash = path.lastIndexOf("/");
  const dot = path.lastIndexOf(".");
  const hasExt = dot > slash + 1;
  const stem = hasExt ? path.slice(0, dot) : path;
  const ext = hasExt ? path.slice(dot) : "";
  const pad = (x: number) => String(x).padStart(2, "0");
  const ts = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}${pad(now.getMinutes())}`;
  return `${stem} (conflict ${device} ${ts}${n ? ` ${n}` : ""})${ext}`;
}

/** Serializes async work: run() calls never overlap. */
export class Mutex {
  private tail: Promise<unknown> = Promise.resolve();
  run<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.tail.then(fn, fn);
    this.tail = next.catch(() => undefined);
    return next;
  }
}
