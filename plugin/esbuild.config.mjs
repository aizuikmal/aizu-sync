import esbuild from "esbuild";
import builtins from "builtin-modules";
import process from "process";

const isWatch = process.argv.includes("--watch");
const prod = process.env.BUILD === "production";

const context = await esbuild.context({
  entryPoints: ["src/main.ts"],
  bundle: true,
  external: [
    "obsidian", "electron",
    "@codemirror/autocomplete", "@codemirror/collab", "@codemirror/commands",
    "@codemirror/language", "@codemirror/lint", "@codemirror/search",
    "@codemirror/state", "@codemirror/view",
    "@lezer/common", "@lezer/highlight", "@lezer/lr",
    ...builtins,
  ],
  format: "cjs",
  target: "es2020",
  logLevel: "info",
  sourcemap: prod ? false : "inline",
  treeShaking: true,
  outfile: "main.js",
});

if (isWatch) {
  await context.watch();
} else {
  await context.rebuild();
  process.exit(0);
}
