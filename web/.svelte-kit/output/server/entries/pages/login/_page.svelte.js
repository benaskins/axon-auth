import { b as attr } from "../../../chunks/attributes.js";
import { e as escape_html } from "../../../chunks/escaping.js";
import "@sveltejs/kit/internal";
import "../../../chunks/exports.js";
import "../../../chunks/utils.js";
import "@sveltejs/kit/internal/server";
import "../../../chunks/state.svelte.js";
import "@simplewebauthn/browser";
function _page($$renderer, $$props) {
  $$renderer.component(($$renderer2) => {
    let email = "";
    let loading = false;
    {
      $$renderer2.push("<!--[!-->");
      $$renderer2.push(`<div class="container svelte-1x05zx6"><div class="card svelte-1x05zx6"><h1 class="svelte-1x05zx6">Sign In</h1> <p class="subtitle svelte-1x05zx6">Aurelia Studio</p> `);
      {
        $$renderer2.push("<!--[!-->");
      }
      $$renderer2.push(`<!--]--> <form><div class="field svelte-1x05zx6"><label for="email" class="svelte-1x05zx6">Email</label> <input id="email" type="email"${attr("value", email)} placeholder="you@example.com"${attr("disabled", loading, true)} required="" class="svelte-1x05zx6"/></div> <button type="submit" class="primary-btn svelte-1x05zx6"${attr("disabled", !email.trim(), true)}>${escape_html("Sign in with Passkey")}</button></form></div></div>`);
    }
    $$renderer2.push(`<!--]-->`);
  });
}
export {
  _page as default
};
