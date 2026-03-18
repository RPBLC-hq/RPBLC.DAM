#!/usr/bin/env node

const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const PLATFORMS = {
  "linux-x64": "@rpblc/dam-linux-x64",
  "darwin-arm64": "@rpblc/dam-darwin-arm64",
  "darwin-x64": "@rpblc/dam-darwin-x64",
  "win32-x64": "@rpblc/dam-win32-x64",
};

function getBinaryPath() {
  const key = `${process.platform}-${process.arch}`;
  const pkg = PLATFORMS[key];

  if (!pkg) {
    console.error(
      `Unsupported platform: ${process.platform}-${process.arch}`
    );
    console.error(`Supported: ${Object.keys(PLATFORMS).join(", ")}`);
    process.exit(1);
  }

  try {
    const pkgDir = path.dirname(require.resolve(`${pkg}/package.json`));
    const binary = process.platform === "win32" ? "dam.exe" : "dam";
    return path.join(pkgDir, "bin", binary);
  } catch {
    console.error(`Could not find binary package: ${pkg}`);
    console.error(`Try reinstalling: npm install -g @rpblc/dam`);
    process.exit(1);
  }
}

const binary = getBinaryPath();

if (!fs.existsSync(binary)) {
  console.error(`Binary not found at ${binary}`);
  console.error(`The package may be corrupted. Try reinstalling: npm install -g @rpblc/dam`);
  process.exit(1);
}

const args = process.argv.slice(2);

try {
  execFileSync(binary, args, { stdio: "inherit" });
} catch (err) {
  if (err.status !== undefined) {
    process.exit(err.status);
  }
  throw err;
}
