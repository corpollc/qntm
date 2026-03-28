export async function runStoppablePassiveMonitor<TMonitor extends { stop: () => void }>(params: {
  abortSignal: AbortSignal;
  start: () => Promise<TMonitor>;
}): Promise<void> {
  const monitor = await params.start();

  await new Promise<void>((resolve) => {
    if (params.abortSignal.aborted) {
      resolve();
      return;
    }
    params.abortSignal.addEventListener("abort", () => resolve(), { once: true });
  });

  monitor.stop();
}
