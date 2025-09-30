const menuBtn = document.getElementById('menuBtn');
const sideMenu = document.getElementById('sideMenu');
const closeBtn = document.getElementById('closeMenuBtn');
const overlay = document.getElementById('overlay');

function openMenu() {
  sideMenu.classList.add('open');
  overlay.classList.remove('hidden');
}

function closeMenu() {
  sideMenu.classList.remove('open');
  overlay.classList.add('hidden');
}

// Toggle menu
menuBtn.addEventListener('click', () => {
  if (sideMenu.classList.contains('open')) {
    closeMenu();
  } else {
    openMenu();
  }
});

closeBtn.addEventListener('click', closeMenu);
overlay.addEventListener('click', closeMenu);

// Optional: ESC key closes menu
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeMenu();
});
