#!/usr/bin/env node
import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = process.cwd();
const args = process.argv.slice(2);
const option = (name) => args.includes(name) ? args[args.indexOf(name) + 1] : undefined;
if (args.includes('--help')) {
  console.log('Usage: npm run harness:init -- [--name <project-name>] [--description <text>]');
  process.exit(0);
}
const name = option('--name') || path.basename(root);
const description = option('--description') || `Project ${name} using the Codex harness.`;
const templateRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

async function exists(file) { try { await access(file); return true; } catch { return false; } }
async function writeIfAbsent(relative, contents) {
  const target = path.join(root, relative);
  if (await exists(target)) { console.log(`kept ${relative}`); return; }
  await mkdir(path.dirname(target), { recursive: true });
  await writeFile(target, contents, 'utf8');
  console.log(`created ${relative}`);
}

const configFile = path.join(root, 'harness.config.json');
if (!(await exists(configFile))) {
  await writeIfAbsent('harness.config.json', await readFile(path.join(templateRoot, 'harness.config.json'), 'utf8'));
}
const config = JSON.parse(await readFile(configFile, 'utf8'));
if (config.project?.name === 'replace-with-project-name') {
  config.project.name = name;
  config.project.description = description;
  await writeFile(configFile, `${JSON.stringify(config, null, 2)}\n`, 'utf8');
  console.log('configured harness.config.json project identity');
} else {
  console.log('kept harness.config.json project identity');
}
await writeIfAbsent('docs/project.md', `# ${name}\n\n${description}\n\n## Project identity\n\n- Name: ${name}\n- Harness setup: ${new Date().toISOString()}\n`);
