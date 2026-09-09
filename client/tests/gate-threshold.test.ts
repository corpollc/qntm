import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { lookupThreshold } from '../src/index.js';
import type { ThresholdRule } from '../src/index.js';

const cases = JSON.parse(readFileSync(new URL('../../specs/test-vectors/gateway-thresholds.json', import.meta.url), 'utf8')) as Array<{
  name: string; rules: ThresholdRule[]; service: string; endpoint: string; verb: string; expected_index: number | null;
}>;
describe('shared gateway policy selection', () => {
  it.each(cases)('$name', ({ rules, service, endpoint, verb, expected_index }) => {
    expect(lookupThreshold(rules, service, endpoint, verb)).toBe(expected_index === null ? undefined : rules[expected_index]);
  });
});
