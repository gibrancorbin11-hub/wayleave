(function () {
  'use strict';

  /* ---------- Theme toggle (in-memory only, no localStorage) ---------- */
  var root = document.documentElement;
  var prefersLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
  var currentTheme = prefersLight ? 'light' : 'dark';
  root.setAttribute('data-theme', currentTheme);

  var themeToggle = document.getElementById('themeToggle');
  var iconSun = document.getElementById('iconSun');
  var iconMoon = document.getElementById('iconMoon');

  function syncIcons() {
    if (currentTheme === 'dark') {
      iconSun.style.display = 'none';
      iconMoon.style.display = 'block';
    } else {
      iconSun.style.display = 'block';
      iconMoon.style.display = 'none';
    }
  }
  syncIcons();

  themeToggle.addEventListener('click', function () {
    currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', currentTheme);
    syncIcons();
  });

  /* ---------- Copy-to-clipboard for install command ---------- */
  var copyBtn = document.getElementById('copyInstall');
  var copyIcon = document.getElementById('copyIcon');
  var checkIcon = document.getElementById('checkIcon');

  copyBtn.addEventListener('click', function () {
    var text = 'npm i wayleave';
    function showCopied() {
      copyIcon.style.display = 'none';
      checkIcon.style.display = 'block';
      setTimeout(function () {
        copyIcon.style.display = 'block';
        checkIcon.style.display = 'none';
      }, 1600);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(showCopied).catch(showCopied);
    } else {
      showCopied();
    }
  });

  /* ---------- Lane sorter demo: simulated traffic ---------- */
  var lanes = [
    { key: 'verified_agent', result: '✓ paid', label: 'verified_agent' },
    { key: 'declared_agent', result: '402', label: 'declared_agent' },
    { key: 'suspected_bot', result: '402', label: 'suspected_bot' },
    { key: 'human', result: 'free pass', label: 'human' }
  ];
  var counterEl = document.getElementById('demoCounter');
  var count = 0;
  var packetSamples = {
    verified_agent: ['GET /api/products', 'POST /v1/search', 'GET /docs/schema'],
    declared_agent: ['GET /sitemap.xml', 'GET /api/prices', 'GET /rss.xml'],
    suspected_bot: ['GET /api/inventory', 'POST /v1/query', 'GET /export.csv'],
    human: ['GET /checkout', 'GET /dashboard', 'GET /account']
  };

  var busyLanes = {};

  function spawnPacket(laneKey) {
    var track = document.querySelector('.demo__track[data-track="' + laneKey + '"]');
    if (!track || busyLanes[laneKey]) return false;
    busyLanes[laneKey] = true;
    var samples = packetSamples[laneKey];
    var text = samples[Math.floor(Math.random() * samples.length)];
    var chip = document.createElement('span');
    chip.className = 'demo__packet';
    chip.textContent = text;
    track.appendChild(chip);
    count += 1;
    if (counterEl) counterEl.textContent = count.toLocaleString();
    setTimeout(function () {
      if (chip.parentNode) chip.parentNode.removeChild(chip);
      busyLanes[laneKey] = false;
    }, 2700);
    return true;
  }

  function tick() {
    var freeLanes = lanes.filter(function (l) { return !busyLanes[l.key]; });
    if (freeLanes.length === 0) return;
    var lane = freeLanes[Math.floor(Math.random() * freeLanes.length)];
    spawnPacket(lane.key);
  }

  var demoInterval = null;
  var reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var demoEl = document.getElementById('demoBody');

  function startDemo() {
    if (demoInterval || reduceMotion) return;
    tick();
    demoInterval = setInterval(tick, 950);
  }
  function stopDemo() {
    clearInterval(demoInterval);
    demoInterval = null;
  }

  if (demoEl && 'IntersectionObserver' in window) {
    var demoObserver = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          startDemo();
        } else {
          stopDemo();
        }
      });
    }, { threshold: 0.2 });
    demoObserver.observe(demoEl);
  } else {
    startDemo();
  }

  /* ---------- Waitlist form (static preview — no backend) ---------- */
  var joinForm = document.getElementById('joinForm');
  var waitlistWrap = document.getElementById('waitlistForm');

  if (joinForm) {
    joinForm.addEventListener('submit', function (e) {
      e.preventDefault();

      var submitBtn = joinForm.querySelector('button[type="submit"]');
      var errorEl = document.getElementById('joinError');
      if (errorEl) { errorEl.hidden = true; }
      if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = 'Joining…'; }

      /* Netlify Forms accepts a urlencoded POST to the page path as long as
         form-name is included. Only reveal the success state if the POST
         actually succeeded — a form that claims success while dropping the
         signup is worse than one that visibly fails. */
      fetch('/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams(new FormData(joinForm)).toString()
      })
        .then(function (res) {
          if (!res.ok) { throw new Error('HTTP ' + res.status); }
          waitlistWrap.classList.add('is-submitted');
        })
        .catch(function () {
          if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = 'Join the waitlist'; }
          if (errorEl) {
            errorEl.hidden = false;
          } else {
            /* No-JS-error element in the DOM: fall back to a real submit so
               the signup is never silently lost. */
            joinForm.submit();
          }
        });
    });
  }

  /* ---------- Scroll reveal ---------- */
  var revealEls = document.querySelectorAll('.reveal');
  if ('IntersectionObserver' in window && !reduceMotion) {
    var revealObserver = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          revealObserver.unobserve(entry.target);
        }
      });
    }, { threshold: 0.15, rootMargin: '0px 0px -40px 0px' });
    revealEls.forEach(function (el) {
      revealObserver.observe(el);
    });
  } else {
    revealEls.forEach(function (el) {
      el.classList.add('is-visible');
    });
  }

  /* ---------- Mobile nav fallback (nav hidden below 860px; use anchor scroll) ---------- */
  document.querySelectorAll('a[href^="#"]').forEach(function (anchor) {
    anchor.addEventListener('click', function (e) {
      var id = this.getAttribute('href').slice(1);
      var target = document.getElementById(id);
      if (target) {
        e.preventDefault();
        target.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' });
      }
    });
  });
})();
