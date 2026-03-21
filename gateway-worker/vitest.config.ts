import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  resolve: {
    alias: {
      'cloudflare:workers': path.resolve(__dirname, 'src/__mocks__/cloudflare-workers.ts'),
    },
  },
  test: {
    globals: true,
  },
});
