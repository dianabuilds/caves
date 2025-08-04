(function () {
  const b = document.getElementById('data-consent');
  if (!b) return;
  if (localStorage.getItem('data-consent')) {
    b.remove();
    return;
  }
  const btn = document.getElementById('consent-ok');
  btn?.addEventListener('click', () => {
    localStorage.setItem('data-consent', '1');
    b.remove();
  });
})();
