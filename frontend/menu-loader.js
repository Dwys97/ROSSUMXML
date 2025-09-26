// menu-loader.js
export function loadMenu() {
  const placeholder = document.getElementById('menu-placeholder');
  if (!placeholder) return;

  fetch('menu.html')
    .then(res => res.text())
    .then(html => {
      placeholder.innerHTML = html;
      // Once menu is loaded, import the menu.js
      const script = document.createElement('script');
      script.src = 'menu.js';
      document.body.appendChild(script);
    })
    .catch(err => console.error('Failed to load menu:', err));
}

// Call the loader
loadMenu();
