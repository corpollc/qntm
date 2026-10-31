(() => {
  'use strict';

  const status = document.getElementById('checkpoint-status');
  const values = document.getElementById('checkpoint-values');
  const refresh = document.getElementById('checkpoint-refresh');
  const hash = /^[0-9a-f]{64}$/;
  const timestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;

  async function loadCheckpoint() {
    refresh.disabled = true;
    values.hidden = true;
    status.hidden = false;
    status.textContent = 'Loading the registry checkpoint…';
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch('/v1/heads', {
        cache: 'no-store', credentials: 'omit', redirect: 'error', signal: controller.signal,
        headers: { Accept: 'application/json' },
      });
      if (!response.ok) throw new Error('Checkpoint unavailable');
      const heads = await response.json();
      const epoch = heads?.epoch?.signed;
      const log = heads?.log?.signed;
      if (!epoch || !log || epoch.kind !== 'charter.epoch' || log.kind !== 'charter.log' ||
          epoch.registry !== 'charter.qntm.corpo.llc' || log.registry !== epoch.registry ||
          typeof epoch.map_root !== 'string' || !hash.test(epoch.map_root) ||
          typeof log.root_hash !== 'string' || !hash.test(log.root_hash) ||
          epoch.log_root !== log.root_hash || !Number.isSafeInteger(log.tree_size) || log.tree_size < 0 ||
          epoch.map_size !== log.tree_size || epoch.log_size !== log.tree_size || epoch.epoch !== log.tree_size ||
          typeof epoch.timestamp !== 'string' || !timestamp.test(epoch.timestamp) ||
          epoch.timestamp !== log.timestamp || !Number.isFinite(Date.parse(epoch.timestamp))) {
        throw new Error('Invalid checkpoint');
      }
      document.getElementById('checkpoint-map').textContent = epoch.map_root;
      document.getElementById('checkpoint-log').textContent = log.root_hash;
      const time = document.getElementById('checkpoint-time');
      time.dateTime = epoch.timestamp;
      time.textContent = new Date(epoch.timestamp).toLocaleString('en-US', {
        timeZone: 'UTC', year: 'numeric', month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
      });
      document.getElementById('checkpoint-size').textContent = log.tree_size.toLocaleString('en-US');
      values.hidden = false;
      status.textContent = 'Registry checkpoint loaded.';
      status.hidden = true;
    } catch {
      status.textContent = 'Could not load the registry checkpoint. Try Refresh or open the signed checkpoint JSON below.';
    } finally {
      clearTimeout(timeout);
      refresh.disabled = false;
    }
  }

  refresh.hidden = false;
  refresh.addEventListener('click', loadCheckpoint);
  loadCheckpoint();
})();
