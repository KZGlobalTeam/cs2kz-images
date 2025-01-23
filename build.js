const { build } = require("esbuild");

build({
  entryPoints: ["src/index.ts"],
  outfile: "dist/index.js",
  bundle: true,
  platform: "node",
  target: "node20",
  sourcemap: false,
  external: ["fs", "path"],
  format: "cjs",
})
  .then(() => console.log("Build succeeded."))
  .catch(() => process.exit(1));
