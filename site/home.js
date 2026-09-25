(() => {
  const status = document.getElementById('copyStatus');
  let timer;
  document.querySelectorAll('[data-copy], [data-copy-target]').forEach(button => {
    button.addEventListener('click', async () => {
      const text = button.dataset.copy || document.getElementById(button.dataset.copyTarget).textContent;
      try {
        if (!navigator.clipboard) throw new Error('Clipboard unavailable');
        await navigator.clipboard.writeText(text);
        status.textContent = 'Copied to clipboard.';
      } catch {
        status.textContent = 'Could not copy. Select the command or code and copy it manually.';
      }
      clearTimeout(timer);
      timer = setTimeout(() => { status.textContent = ''; }, 6000);
    });
  });
  document.getElementById('trafficFilter').addEventListener('change', event => {
    document.querySelectorAll('[data-lane]').forEach(row => {
      row.hidden = event.target.value !== 'all' && row.dataset.lane !== event.target.value;
    });
  });
  const toggle = document.getElementById('themeToggle');
  toggle.addEventListener('click', () => {
    const light = document.documentElement.dataset.theme !== 'light';
    document.documentElement.dataset.theme = light ? 'light' : 'dark';
    toggle.setAttribute('aria-label', light ? 'Switch to dark theme' : 'Switch to light theme');
  });
})();

/* Replace the sample figures with what the meter actually recorded.
 *
 * The page ships with illustrative numbers and says so on the badge. If the
 * meter answers, they are swapped for real counts and the badge changes to
 * match. If it does not answer, nothing moves and the badge keeps saying
 * SAMPLE DATA -- which is true, and better than a page that blanks out or
 * shows zeros because a fetch failed.
 *
 * Note for anyone adding another fetch here: netlify.toml sets
 * connect-src, so a new origin must be listed there or the browser blocks
 * the request silently and this file looks broken.
 */
(() => {
  const el = id => document.getElementById(id);
  const badge = el('dataBadge');
  if (!badge) return;

  const nf = new Intl.NumberFormat('en-US');
  const set = (id, value) => { const n = el(id); if (n) n.textContent = nf.format(value); };

  const controller = new AbortController();
  setTimeout(() => controller.abort(), 4000);

  fetch('https://meter.wayleave.dev/v1/public/stats', { signal: controller.signal })
    .then(r => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))))
    .then(s => {
      if (!Number.isFinite(s?.crossings)) throw new Error('unexpected shape');
      set('statCrossings', s.agentCrossings);
      set('statVerified', s.verifiedAgents);
      set('statPriced', s.paymentRequired);
      badge.textContent = 'LIVE';
      badge.title = `Recorded by meter.wayleave.dev. ${nf.format(s.crossings)} total crossings.`;
    })
    .catch(() => { /* leave the sample figures and the badge exactly as they are */ });
})();
