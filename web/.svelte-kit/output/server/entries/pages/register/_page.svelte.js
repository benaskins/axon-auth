import "clsx";
import "@sveltejs/kit/internal";
import "../../../chunks/exports.js";
import "../../../chunks/utils.js";
import "@sveltejs/kit/internal/server";
import "../../../chunks/state.svelte.js";
import "@simplewebauthn/browser";
function _page($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    $$renderer2.push(`<div class="container svelte-52fghe"><div class="card svelte-52fghe"><h1 class="svelte-52fghe">Create Account</h1> <p class="subtitle svelte-52fghe">Aurelia Studio</p> `);
    {
      $$renderer2.push("<!--[-->");
      $$renderer2.push(`<div class="loading-state svelte-52fghe"><p>Validating invite...</p></div>`);
    }
    $$renderer2.push(`<!--]--></div></div>`);
  });
}
export {
  _page as default
};
