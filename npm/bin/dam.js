#!/usr/bin/env node
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const ROOT = path.resolve(__dirname, "..", "..");
const NATIVE_DIR = path.join(ROOT, "npm", "native");
const TRIAL_COMMANDS = new Set(["claude", "codex"]);

function main() {
  const rawArgs = process.argv.slice(2);
  const command = rawArgs[0];

  if (!command || command === "-h" || command === "--help" || command === "help") {
    runNative("dam", rawArgs);
    return;
  }

  if (command === "doctor") {
    doctor();
    return;
  }

  if (command === "web") {
    runNative("dam-web", rawArgs.slice(1));
    return;
  }

  const flags = splitWrapperFlags(rawArgs);
  if (TRIAL_COMMANDS.has(command) && shouldRunTrial(flags)) {
    runTrial(command, flags.args.slice(1), flags.keep);
    return;
  }

  runNative("dam", flags.args);
}

function splitWrapperFlags(args) {
  const separator = args.indexOf("--");
  const beforeToolArgs = separator === -1 ? args : args.slice(0, separator);
  const afterToolArgs = separator === -1 ? [] : args.slice(separator);
  const stripped = [];
  let trial = false;
  let persist = false;
  let keep = false;

  for (const arg of beforeToolArgs) {
    if (arg === "--trial") {
      trial = true;
    } else if (arg === "--persist") {
      persist = true;
    } else if (arg === "--keep") {
      keep = true;
    } else {
      stripped.push(arg);
    }
  }

  return {
    args: stripped.concat(afterToolArgs),
    trial,
    persist,
    keep,
  };
}

function shouldRunTrial(flags) {
  if (flags.persist) {
    return false;
  }
  return flags.trial || invokedThroughNpx();
}

function invokedThroughNpx() {
  const probe = `${__dirname}${path.delimiter}${process.argv[1] || ""}`;
  return /(^|[\\/])_npx([\\/]|$)/.test(probe) || /[\\/]npm-cache[\\/]_npx[\\/]/.test(probe);
}

function runTrial(command, args, keep) {
  const trialDir = fs.mkdtempSync(path.join(os.tmpdir(), "dam-trial-"));
  const vaultPath = path.join(trialDir, "vault.db");
  const logPath = path.join(trialDir, "log.db");
  const consentPath = path.join(trialDir, "consent.db");
  const launchArgs = buildTrialArgs(command, args, vaultPath, logPath, consentPath);

  process.stderr.write("DAM trial mode\n\n");
  process.stderr.write(`✓ Vault: ${vaultPath}\n`);
  process.stderr.write(`✓ Logs: ${logPath}\n`);
  process.stderr.write(`✓ Consents: ${consentPath}\n`);
  process.stderr.write(`✓ Keep data: ${keep ? "yes" : "no"}\n\n`);
  process.stderr.write(`Launching ${command} through DAM...\n`);

  const env = {
    ...process.env,
    DAM_CONSENT_PATH: consentPath,
    DAM_CONSENT_SQLITE_PATH: consentPath,
  };
  const result = spawnNative("dam", launchArgs, { env });

  if (!keep) {
    fs.rmSync(trialDir, { force: true, recursive: true });
  } else {
    process.stderr.write(`\nDAM trial data kept at ${trialDir}\n`);
  }

  process.exit(result.status ?? 1);
}

function buildTrialArgs(command, args, vaultPath, logPath, consentPath) {
  const separator = args.indexOf("--");
  const damArgs = separator === -1 ? args.slice() : args.slice(0, separator);
  const toolArgs = separator === -1 ? [] : args.slice(separator);

  ensureOption(damArgs, "--db", vaultPath);
  if (!damArgs.includes("--no-log")) {
    ensureOption(damArgs, "--log", logPath);
  }
  ensureOption(damArgs, "--consent-db", consentPath);

  return [command, ...damArgs, ...toolArgs];
}

function ensureOption(args, option, value) {
  if (args.includes(option)) {
    return;
  }
  args.push(option, value);
}

function doctor() {
  const rows = [];
  rows.push(checkBinary("dam"));
  rows.push(checkBinary("dam-proxy"));
  rows.push(checkBinary("dam-web"));
  rows.push(checkBinary("dam-mcp"));
  rows.push(checkOnPath("claude", "Claude Code"));
  rows.push(checkOnPath("codex", "Codex"));

  process.stdout.write("DAM doctor\n\n");
  for (const row of rows) {
    process.stdout.write(`${row.ok ? "✓" : "!"} ${row.label}${row.detail ? `: ${row.detail}` : ""}\n`);
  }

  process.exit(rows.every((row) => row.ok) ? 0 : 1);
}

function checkBinary(name) {
  try {
    return { ok: true, label: `${name} binary`, detail: resolveNative(name) };
  } catch (error) {
    return { ok: false, label: `${name} binary`, detail: error.message };
  }
}

function checkOnPath(name, label) {
  const found = findOnPath(nativeName(name));
  return {
    ok: Boolean(found),
    label,
    detail: found || "not found on PATH",
  };
}

function runNative(name, args) {
  const result = spawnNative(name, args, { env: process.env });
  process.exit(result.status ?? 1);
}

function spawnNative(name, args, options) {
  const binary = resolveNative(name);
  return spawnSync(binary, args, {
    env: options.env,
    stdio: "inherit",
  });
}

function resolveNative(name) {
  const envKey = `DAM_NATIVE_${name.toUpperCase().replace(/-/g, "_")}`;
  if (process.env[envKey]) {
    return process.env[envKey];
  }

  const platformDir = `${process.platform}-${process.arch}`;
  const bundled = path.join(NATIVE_DIR, platformDir, nativeName(name));
  if (fs.existsSync(bundled)) {
    return bundled;
  }

  for (const buildDir of ["release", "debug"]) {
    const devBinary = path.join(ROOT, "target", buildDir, nativeName(name));
    if (fs.existsSync(devBinary)) {
      return devBinary;
    }
  }

  const pathBinary = findOnPath(nativeName(name));
  if (pathBinary && !isCurrentScript(pathBinary)) {
    return pathBinary;
  }

  throw new Error(
    `missing ${name} native binary for ${platformDir}; expected ${bundled} or set ${envKey}`
  );
}

function nativeName(name) {
  return process.platform === "win32" ? `${name}.exe` : name;
}

function findOnPath(name) {
  const pathValue = process.env.PATH || "";
  for (const dir of pathValue.split(path.delimiter)) {
    if (!dir) {
      continue;
    }
    const candidate = path.join(dir, name);
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

function isCurrentScript(candidate) {
  try {
    const current = process.argv[1] ? fs.realpathSync(process.argv[1]) : "";
    return fs.realpathSync(candidate) === current;
  } catch {
    return path.resolve(candidate) === path.resolve(process.argv[1] || "");
  }
}

main();
