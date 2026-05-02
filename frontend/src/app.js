import { renderRoute } from './router.js';

const root = document.querySelector('#app');

if (root) {
    renderRoute(root, window.location);
}
