#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { readConfig, validateConfig } from './lib/config.mjs';

const root = process.cwd();
const args = process.argv.slice(2);
if (args.includes('--help')) {
  console.log('Usage: npm run harness:check -- [--run-adapters] [--adapter <name>]');
  console.log('Default behavior is dry validation: adapter commands are listed but not executed. Use --run-adapters to execute active adapter commands.');
  process.exit(0);
}
const runAdapters = args.includes('--run-adapters');
const selected = args.flatMap((value, index) => value === '--adapter' && args[index + 1] ? [args[index + 1]] : []);
let config;
try { config = await readConfig(root); }
catch (error) { console.error(`FAIL ${error.message}`); process.exit(1); }
let errors = validateConfig(config);
try {
  const paperthinLock = JSON.parse(await readFile(path.join(root, 'harness/paperthin.lock'), 'utf8'));
  if (paperthinLock.revision !== config.paperthin?.ref) errors.push('paperthin.ref must match harness/paperthin.lock revision');
} catch (error) {
  errors.push(`cannot read harness/paperthin.lock: ${error.message}`);
}
try {
  const grillMeLock = JSON.parse(await readFile(path.join(root, 'harness/grill-me.lock'), 'utf8'));
  if (grillMeLock.dependency !== 'grill-me') errors.push('harness/grill-me.lock dependency must be grill-me');
  if (typeof grillMeLock.repository !== 'string' || !grillMeLock.repository) errors.push('harness/grill-me.lock repository must be a non-empty string');
  if (typeof grillMeLock.revision !== 'string' || !grillMeLock.revision) errors.push('harness/grill-me.lock revision must be a non-empty string');
} catch (error) {
  errors.push(`cannot read harness/grill-me.lock: ${error.message}`);
}
const active = selected.length ? selected : (config.adapters?.active ?? []);
for (const adapter of active) {
  const commands = config.adapters?.definitions?.[adapter]?.commands;
  if (!commands || typeof commands !== 'object') { errors.push(`adapter '${adapter}' has no commands object`); continue; }
  const testPolicy = config.adapters?.definitions?.[adapter]?.testPolicy;
  if (!testPolicy || !Array.isArray(testPolicy.platforms) || !testPolicy.platforms.includes('linux') || testPolicy.localOnly !== false || testPolicy.vendorNeutral !== true) errors.push(`adapter '${adapter}' must declare Linux, vendor-neutral, non-local-only required tests`);
  for (const [name, command] of Object.entries(commands)) if (typeof command !== 'string' || !command.trim()) errors.push(`adapter '${adapter}' command '${name}' must be a non-empty string`);
}
if (errors.length) {
  for (const error of errors) console.error(`FAIL ${error}`);
  process.exit(1);
}
console.log('PASS configuration.');
if (!runAdapters) {
  console.log(active.length ? `DRY RUN adapters not executed: ${active.join(', ')}. Re-run with --run-adapters.` : 'SKIP adapters: none are active.');
  process.exit(0);
}
if (!active.length) { console.log('SKIP adapters: none are active.'); process.exit(0); }
for (const adapter of active) for (const [name, command] of Object.entries(config.adapters.definitions[adapter].commands)) {
  console.log(`RUN ${adapter}:${name}: ${command}`);
  const status = await new Promise((resolve) => {
    spawn(command, { cwd: root, shell: true, stdio: 'inherit' }).on('exit', (code) => resolve(code ?? 1));
  });
  if (status !== 0) errors.push(`adapter '${adapter}' command '${name}' exited ${status}`);
}
if (errors.length) { for (const error of errors) console.error(`FAIL ${error}`); process.exit(1); }
console.log('PASS adapter commands.');
