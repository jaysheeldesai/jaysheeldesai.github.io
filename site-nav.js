(() => {
  const header = document.querySelector('.site-header');
  const toggle = header?.querySelector('.menu-toggle');
  const nav = header?.querySelector('nav');
  if (!header || !toggle || !nav) return;
  let closeTimer;
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

  const glideTo = (target, hash) => {
    const headerOffset = header.getBoundingClientRect().height + 18;
    const start = window.scrollY;
    const destination = Math.max(0, target.getBoundingClientRect().top + start - headerOffset);
    const distance = destination - start;
    const duration = Math.min(1300, Math.max(850, Math.abs(distance) * 0.14));

    if (reducedMotion.matches) {
      window.scrollTo(0, destination);
      history.pushState(null, '', hash);
      return;
    }

    const previousBehavior = document.documentElement.style.scrollBehavior;
    document.documentElement.style.scrollBehavior = 'auto';
    const startedAt = performance.now();
    const ease = (value) => value < 0.5
      ? 4 * value * value * value
      : 1 - Math.pow(-2 * value + 2, 3) / 2;

    const step = (now) => {
      const progress = Math.min(1, (now - startedAt) / duration);
      window.scrollTo(0, start + distance * ease(progress));
      if (progress < 1) {
        requestAnimationFrame(step);
        return;
      }
      document.documentElement.style.scrollBehavior = previousBehavior;
      history.pushState(null, '', hash);
      target.setAttribute('tabindex', '-1');
      target.focus({ preventScroll: true });
    };

    requestAnimationFrame(step);
  };

  const close = (immediate = false) => {
    clearTimeout(closeTimer);
    toggle.setAttribute('aria-expanded', 'false');
    toggle.setAttribute('aria-label', 'Open navigation menu');
    if (immediate || !nav.classList.contains('is-open')) {
      nav.classList.remove('is-open', 'is-closing');
      return;
    }
    nav.classList.add('is-closing');
    closeTimer = setTimeout(() => {
      nav.classList.remove('is-open', 'is-closing');
    }, 280);
  };

  toggle.addEventListener('click', () => {
    const opening = !nav.classList.contains('is-open');
    clearTimeout(closeTimer);
    if (opening) {
      nav.classList.remove('is-closing');
      nav.classList.add('is-open');
    } else {
      close();
      return;
    }
    toggle.setAttribute('aria-expanded', String(opening));
    toggle.setAttribute('aria-label', opening ? 'Close navigation menu' : 'Open navigation menu');
  });

  nav.addEventListener('click', (event) => {
    const link = event.target.closest('a');
    if (!link) return;
    const href = link.getAttribute('href');
    if (!href?.startsWith('#')) {
      close();
      return;
    }
    const target = document.querySelector(href);
    if (!target) return;
    event.preventDefault();
    const compactHeader = window.matchMedia('(max-width: 1180px)').matches;
    close();
    setTimeout(() => glideTo(target, href), compactHeader ? 260 : 0);
  });

  document.addEventListener('click', (event) => {
    if (!header.contains(event.target)) close();
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      close();
      toggle.focus();
    }
  });

  window.matchMedia('(min-width: 1181px)').addEventListener('change', () => close(true));
})();
