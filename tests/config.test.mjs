import test from 'node:test';
import assert from 'node:assert/strict';
import { readConfig, validateConfig } from '../scripts/lib/config.mjs';

test('default harness configuration is valid', async () => {
  const config = await readConfig(process.cwd());
  assert.deepEqual(validateConfig(config), []);
});
