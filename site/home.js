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
