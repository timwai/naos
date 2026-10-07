import { mkdirSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const webRoot = resolve(scriptDir, "..");
const repoRoot = resolve(webRoot, "..");
const generatedDir = resolve(webRoot, ".generated");
const schemaPath = resolve(generatedDir, "openapi.json");
const outputPath = resolve(webRoot, "src/lib/api/generated.ts");

mkdirSync(generatedDir, { recursive: true });
mkdirSync(dirname(outputPath), { recursive: true });

const cargo = spawnSync(
  "cargo",
  ["run", "--quiet", "-p", "naosd", "--", "export-openapi"],
  {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
  },
);

if (cargo.status !== 0 || !cargo.stdout) {
  process.exit(cargo.status ?? 1);
}

JSON.parse(cargo.stdout);
writeFileSync(schemaPath, cargo.stdout);

const npx = process.platform === "win32" ? "npx.cmd" : "npx";
const generator = spawnSync(
  npx,
  ["--no-install", "openapi-typescript", schemaPath, "-o", outputPath],
  {
    cwd: webRoot,
    stdio: "inherit",
  },
);

process.exit(generator.status ?? 1);
