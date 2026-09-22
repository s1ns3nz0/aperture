import { readFile } from 'node:fs/promises';
import path from 'node:path';

export const CONFIG_FILE = 'harness.config.json';
export async function readConfig(root) { return JSON.parse(await readFile(path.join(root, CONFIG_FILE), 'utf8')); }
export function validateConfig(config) {
  const errors = [];
  if (config?.schemaVersion !== 1) errors.push('schemaVersion must be 1');
  if (!config?.project?.name) errors.push('project.name is required');
  if (!config?.paperthin?.ref) errors.push('paperthin.ref is required');
  if (config?.policies?.mvpFirst !== true) errors.push('policies.mvpFirst must be true');
  if (!Array.isArray(config?.policies?.grillMe?.appliesTo)) errors.push('policies.grillMe.appliesTo must be an array');
  if (!Array.isArray(config?.policies?.review?.skills) || !config.policies.review.skills.includes('sip') || !config.policies.review.skills.includes('shower')) errors.push('policies.review.skills must include sip and shower');
  const portability = config?.policies?.testPortability;
  if (portability?.requiredPlatform !== 'linux' || portability?.vendorNeutral !== true || portability?.allowLocalOnlyRequired !== false) errors.push('required tests must be Linux-first, vendor-neutral, and non-local-only');
  return errors;
}
