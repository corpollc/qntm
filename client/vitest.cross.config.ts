import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/cross-client.test.ts', 'tests/group-welcome.integration.ts'],
    testTimeout: 30000,
  },
});
