import { defineConfig } from 'vitest/config';
export default defineConfig({test:{include:['tests/charter-server.integration.ts'],hookTimeout:60_000,testTimeout:30_000}});
