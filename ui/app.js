import { renderMarkdown, markdownEditor, validateOverview } from './markdown.js';
(() => {
  "use strict";
  const $ = (s) => document.querySelector(s),
    page = document.body.dataset.page,
    enc = encodeURIComponent;
  let session = null,
    csrf = "";
  const esc = (s) =>
    String(s ?? "").replace(
      /[&<>"']/g,
      (c) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        })[c],
    );
  const url = (ns, name, version) =>
    `/packages/${enc(ns)}/${enc(name)}${version ? "/" + enc(version) : ""}`;
  const date = (v) => {
    const d = new Date(typeof v === "number" ? v * 1000 : v);
    return Number.isNaN(d.getTime())
      ? "Unknown date"
      : d.toLocaleDateString("en", {
          year: "numeric",
          month: "short",
          day: "numeric",
        });
  };
  const size = (n) =>
    n >= 1048576
      ? `${(n / 1048576).toFixed(1)} MiB`
      : n >= 1024
        ? `${(n / 1024).toFixed(1)} KiB`
        : `${n} bytes`;
  function status(selector, message, failed = false) {
    const e = $(selector);
    if (e) {
      e.textContent = message;
      e.className = failed ? "error" : "quiet";
    }
  }
  async function api(path, options = {}) {
    const headers = {
      ...(csrf ? { "X-CSRF-Token": csrf } : {}),
      ...options.headers,
    };
    if (options.json !== undefined) {
      options.body = JSON.stringify(options.json);
      headers["Content-Type"] = "application/json";
    }
    const response = await fetch(path, {
        ...options,
        headers,
        credentials: "same-origin",
      }),
      data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(
        data.error?.message ||
          data.message ||
          `Request failed (${response.status}).`,
      );
      error.status = response.status;
      throw error;
    }
    return data;
  }
  async function loadSession() {
    try {
      const data = await api("/v1/auth/me");
      session = data.user;
      csrf = data.csrf_token || "";
    } catch (e) {
      if (e.status !== 401) status("#page-status", e.message, true);
    }
    document
      .querySelectorAll("[data-anonymous]")
      .forEach((e) => (e.hidden = !!session));
    document
      .querySelectorAll("[data-authenticated]")
      .forEach((e) => (e.hidden = !session));
  }
  function required() {
    if (session) {
      status("#page-status", "");
      return true;
    }
    const e = $("#page-status");
    e.className = "notice";
    e.innerHTML = `Please <a href="/login?next=${enc(location.pathname)}">sign in</a> or <a href="/register?next=${enc(location.pathname)}">create an account</a> to continue.`;
    return false;
  }
  function form(id, message, action) {
    const f = $(id);
    if (!f) return;
    f.addEventListener("submit", async (e) => {
      e.preventDefault();
      const b = f.querySelector("button[type=submit],button:not([type])");
      if (b.disabled) return;
      b.disabled = true;
      status(message, "Working…");
      try {
        await action(new FormData(f));
      } catch (e) {
        status(message, e.message, true);
      } finally {
        b.disabled = false;
      }
    });
  }
  function copy(button, source) {
    $(button)?.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText($(source).textContent);
        $(button).textContent = "Copied";
      } catch {
        $(button).textContent = "Select and copy the text above";
      }
    });
  }
  function cards(items) {
    return items
      .map(
        (p) =>
          `<article class="package-card"><div class="package-top"><span class="package-icon" aria-hidden="true">{ }</span><span class="badge">${esc(p.latest_version || "No active release")}</span></div><div class="namespace">${esc(p.namespace)} /</div><h3><a href="${url(p.namespace, p.name)}">${esc(p.name)}</a></h3><p>${esc(p.description || "A WebAssembly package, ready to explore.")}</p><div class="package-meta"><span>SHA-256 verified</span><time>${esc(date(p.updated_at))}</time></div></article>`,
      )
      .join("");
  }
  async function explore() {
    const params = new URLSearchParams(location.search),
      q = params.get("q") || "",
      offset = Math.max(0, parseInt(params.get("offset"), 10) || 0),
      limit = page === "home" ? 6 : 12;
    if ($("#query")) $("#query").value = q;
    if ($("#results-heading"))
      $("#results-heading").textContent = q
        ? `Results for “${q}”`
        : "All packages";
    try {
      const data = await api(
          `/v1/search?${new URLSearchParams({ q, offset, limit })}`,
        ),
        items = data.items || [];
      $("#packages").innerHTML = items.length
        ? cards(items)
        : `<div class="empty"><h3>${q ? "No matches yet." : "Your next component starts here."}</h3><p>${q ? "Try a different package name or a broader search." : "This registry is ready for its first package. Make it yours."}</p><a class="button secondary" href="${q ? "/explore" : "/publish"}">${q ? "Clear search" : "Publish the first package →"}</a></div>`;
      status(
        "#page-status",
        items.length
          ? `${items.length} package${items.length === 1 ? "" : "s"} shown${offset ? ` · starting at ${offset + 1}` : ""}.`
          : "",
      );
      if ($("#pagination")) {
        const link = (text, n) =>
          `<a class="button secondary small" href="/explore?${new URLSearchParams({ q, offset: n })}">${text}</a>`;
        $("#pagination").innerHTML =
          (offset ? link("← Previous", Math.max(0, offset - limit)) : "") +
          (items.length === limit ? link("Next →", offset + limit) : "");
      }
    } catch (e) {
      status("#page-status", e.message, true);
    }
    if (page === "home")
      try {
        const data = await api("/v1/stats");
        document
          .querySelectorAll("[data-stat]")
          .forEach(
            (e) =>
              (e.textContent = Number(data[e.dataset.stat] || 0).toLocaleString(
                "en",
              )),
          );
      } catch {
        /* Unavailable measurements remain em dashes. */
      }
  }
  function auth() {
    const errors = {
      not_configured: 'GitHub sign-in is not enabled on this registry.',
      invalid_state: 'Your sign-in request expired or changed. Please try again.',
      denied: 'GitHub sign-in was cancelled. You can try again below.',
      registration_disabled: 'New accounts are disabled. Sign in with an existing account.',
      credential_limit: 'You have too many active sessions. Sign in with your password to manage them.',
    };
    const oauthError = new URLSearchParams(location.search).get('oauth_error');
    if (oauthError) status('#oauth-status', errors[oauthError] || 'GitHub sign-in is temporarily unavailable. Please try again.', true);
    api('/v1/auth/providers').then(providers => {
      document.querySelectorAll('[data-github-auth]').forEach(e => { e.hidden = !providers.github; });
    }).catch(() => { /* Email login remains available if provider discovery fails. */ });
    form("#auth-form", "#form-status", async (values) => {
      const password = String(values.get("password") || "");
      if (page === "register" && password !== values.get("confirm"))
        throw new Error("The passwords do not match.");
      await api(`/v1/auth/${page}`, {
        method: "POST",
        json: { email: values.get('email'), password },
      });
      const next = new URLSearchParams(location.search).get("next");
      location.assign(
        ["/publish", "/account"].includes(next) ? next : "/account",
      );
    });
  }
  async function tokens() {
    const data = await api("/v1/account/tokens");
    $("#tokens").innerHTML = data.tokens.length
      ? data.tokens
          .map(
            (t) =>
              `<div class="token-row"><div><strong>${esc(t.name)}</strong><small>${t.expires_at === null ? "Never expires" : `Expires ${esc(date(t.expires_at))}`}</small></div><button class="button small secondary" data-revoke="${esc(t.id)}">Revoke</button></div>`,
          )
          .join("")
      : '<p class="quiet">No personal tokens yet.</p>';
    $("#tokens")
      .querySelectorAll("[data-revoke]")
      .forEach((b) =>
        b.addEventListener("click", async () => {
          b.disabled = true;
          try {
            await api(`/v1/account/tokens/${enc(b.dataset.revoke)}`, {
              method: "DELETE",
            });
            await tokens();
            status("#token-status", "Token revoked.");
          } catch (e) {
            status("#token-status", e.message, true);
            b.disabled = false;
          }
        }),
      );
  }
  function accountNamespaces() {
    const list = $("#owned-namespaces"), more = $("#more-namespaces"), refresh = $("#refresh-namespaces");
    let cursor = null, loading = false;
    const packagesHtml = (items) => items.map((p) =>
      `<li class="owned-package"><div><a href="${url(p.namespace, p.name)}">${esc(p.name)}</a><p>${esc(p.description || "No description yet.")}</p></div><time datetime="${esc(p.updated_at)}">Updated ${esc(date(p.updated_at))}</time></li>`).join("");
    function addNamespace(n) {
      const card = document.createElement("article");
      card.className = "owned-namespace";
      card.innerHTML = `<header class="owned-namespace-header"><div><h3>${esc(n.name)} <span class="badge">${n.visibility === "private" ? "Private" : "Public"}</span></h3><p>${esc(n.description || "Your WebAssembly namespace.")}</p></div><span class="badge">${n.package_count} ${n.package_count === 1 ? "package" : "packages"}</span></header>
        ${n.packages.length ? `<ul class="owned-package-list">${packagesHtml(n.packages)}</ul>` : '<p class="namespace-empty">No packages yet. <a href="/publish">Publish your first package →</a></p>'}
        <p class="namespace-package-status" role="status"></p>
        <button type="button" class="button small secondary" data-more-packages ${n.next_package_cursor ? "" : "hidden"}>Load more packages</button>`;
      const button = card.querySelector("[data-more-packages]");
      let packageCursor = n.next_package_cursor;
      button.addEventListener("click", async () => {
        button.disabled = true;
        const message = card.querySelector(".namespace-package-status");
        message.textContent = "Loading packages…";
        message.className = "namespace-package-status quiet";
        try {
          const data = await api(`/v1/account/namespaces/${enc(n.name)}/packages?after=${enc(packageCursor)}`);
          card.querySelector(".owned-package-list").insertAdjacentHTML("beforeend", packagesHtml(data.packages));
          packageCursor = data.next_cursor;
          button.hidden = !packageCursor;
          message.textContent = "";
        } catch (e) {
          message.textContent = e.message;
          message.className = "namespace-package-status error";
        } finally { button.disabled = false; }
      });
      list.append(card);
    }
    async function load(reset = true) {
      if (loading) return;
      loading = true;
      more.disabled = refresh.disabled = true;
      status("#namespaces-status", "Loading your namespaces…");
      try {
        const data = await api(`/v1/account/namespaces${!reset && cursor ? `?after=${enc(cursor)}` : ""}`);
        if (reset) list.replaceChildren();
        data.namespaces.forEach(addNamespace);
        cursor = data.next_cursor;
        more.hidden = !cursor;
        status("#namespaces-status", list.children.length ? "" : "No namespaces yet. Create one below to start publishing.");
      } catch (e) {
        status("#namespaces-status", `${e.message} Use Refresh to try again.`, true);
      } finally {
        loading = false;
        more.disabled = refresh.disabled = false;
      }
    }
    refresh.addEventListener("click", () => load());
    more.addEventListener("click", () => load(false));
    return load;
  }
  async function account() {
    if (!required()) return;
    $("#account-content").hidden = false;
    $("#account-name").textContent = session.email || session.username;
    $("#avatar").textContent = (session.email || session.username).slice(0, 1).toUpperCase();
    const loadNamespaces = accountNamespaces();
    $("#logout").addEventListener("click", async () => {
      try {
        await api("/v1/auth/logout", { method: "POST", json: {} });
        location.assign("/login");
      } catch (e) {
        status("#page-status", e.message, true);
      }
    });
    form("#namespace-form", "#namespace-status", async (values) => {
      const data = await api("/v1/namespaces", {
        method: "POST",
        json: Object.fromEntries(values),
      });
      status(
        "#namespace-status",
        `Namespace “${data.name}” is yours. You can now publish to it.`,
      );
      await loadNamespaces();
    });
    $("#token-expiration").addEventListener("change", () => {
      const custom = $("#token-expiration").value === "custom";
      $("#token-custom-expiration").hidden = !custom;
      $("#token-days").disabled = !custom;
      $("#token-days").required = custom;
    });
    form("#token-form", "#token-status", async (values) => {
      const choice = values.get("expiration");
      const days = Number(choice === "custom" ? values.get("days") : choice);
      if (choice !== "never" && (!Number.isInteger(days) || days < 1 || days > 3650))
        throw new Error("Choose a duration between 1 and 3650 days.");
      const data = await api("/v1/account/tokens", {
        method: "POST",
        json: { name: values.get("name"), expires_in: choice === "never" ? null : days * 86400 },
      });
      $("#new-token").hidden = false;
      $("#token-secret").textContent = data.token;
      status("#token-status", data.expires_at === null ? "Token created. It remains valid until revoked." : `Token created. Expires ${date(data.expires_at)}.`);
      await tokens();
    });
    copy("#copy-token", "#token-secret");
    await Promise.all([tokens(), loadNamespaces()]);
  }
  async function publish() {
    if (!required()) return;
    markdownEditor($('#publish-overview-editor'));
    const info = await api("/v1/info");
    const maxBytes = Math.min(info.max_blob_bytes, 32 * 1024 * 1024);
    $("#artifact-limit").textContent =
      `Core modules and components. Up to ${size(maxBytes)} per artifact.`;
    $("#publish-form").hidden = false;
    form("#publish-form", "#form-status", async (values) => {
      const overview = validateOverview(String(values.get('overview') || ''));
      const file = values.get("artifact");
      if (!file?.size) throw new Error("Choose a WebAssembly binary.");
      if (file.size > maxBytes)
        throw new Error(`The publishing page accepts artifacts up to ${size(maxBytes)}.`);
      const body = await file.arrayBuffer(),
        bytes = new Uint8Array(body);
      if (
        bytes.length < 8 ||
        bytes[0] !== 0 ||
        bytes[1] !== 97 ||
        bytes[2] !== 115 ||
        bytes[3] !== 109
      )
        throw new Error("This file does not have a WebAssembly binary header.");
      if (!crypto.subtle)
        throw new Error(
          "Use HTTPS or localhost to compute the artifact digest securely.",
        );
      const hash = await crypto.subtle.digest("SHA-256", body),
        digest =
          "sha256:" +
          Array.from(new Uint8Array(hash), (n) =>
            n.toString(16).padStart(2, "0"),
          ).join("");
      const ns = String(values.get("namespace")),
        name = String(values.get("name")),
        version = String(values.get("version")),
        namespace = await api(`/v1/namespaces/${enc(ns)}`);
      if (namespace.owner_username !== session.username)
        throw new Error(
          "You do not own this namespace. Create one in your account settings.",
        );
      status("#form-status", "Uploading and verifying your artifact…");
      await api(`/v1/blobs/${enc(digest)}`, {
        method: "PUT",
        body,
        headers: { "Content-Type": "application/wasm" },
      });
      status("#form-status", "Publishing the immutable release…");
      const manifest = {
        schema: "wasmd.package/v0",
        namespace: ns,
        name,
        version,
        description: values.get("description"),
        artifacts: [
          {
            name: "module",
            digest,
            size: file.size,
            media_type: "application/wasm",
            kind: bytes[4] === 13 ? "component" : "core-module",
          },
        ],
        dependencies: {},
        annotations: {},
      };
      if (values.get("license")) manifest.license = values.get("license");
      if (overview.trim()) manifest.overview = overview;
      await api(`/v1/packages/${enc(ns)}/${enc(name)}/versions`, {
        method: "POST",
        json: manifest,
      });
      location.assign(url(ns, name));
    });
  }
  async function details() {
    const [ns, name, version] = location.pathname
        .split("/")
        .slice(2)
        .map(decodeURIComponent),
      endpoint = `/v1/packages/${enc(ns)}/${enc(name)}`;
    $("#package-title").textContent =
      `${ns}/${name}${version ? ` · ${version}` : ""}`;
    document.title = `${ns}/${name}${version ? ` ${version}` : ""} · Wasmd Registry`;
    const data = await api(endpoint + (version ? "/" + enc(version) : ""));
    status("#page-status", "");
    if (!version) {
      $("#package-description").textContent =
        data.description || "A portable WebAssembly package.";
      $("#package-content").hidden = false;
      packageOverview(data, endpoint, ns, name);
      const latest = data.versions.find((v) => !v.yanked);
      $("#install-command").textContent = latest
        ? `wasmd pull ${ns}/${name}:${latest.version}`
        : "No active releases. Exact versions remain available below.";
      $("#versions").innerHTML = data.versions
        .map(
          (v) =>
            `<div class="release-row"><a href="${url(ns, name, v.version)}">${esc(v.version)} →</a><span class="badge">${v.yanked ? "Yanked" : "Available"}</span><time>${esc(date(v.created_at))}</time></div>`,
        )
        .join("");
    } else {
      const m = data.manifest;
      $("#package-back").href = url(ns, name);
      $("#package-description").textContent = m.description || "";
      $("#release-content").hidden = false;
      $("#install-command").textContent =
        `wasmd pull ${ns}/${name}:${version}`;
      $("#manifest").textContent = JSON.stringify(m, null, 2);
      $("#artifacts").innerHTML = m.artifacts
        .map(
          (a) =>
            `<article class="package-card artifact"><div class="package-top"><h3>${esc(a.name)}</h3><span class="badge">${esc(a.kind)}</span></div><dl><dt>Size</dt><dd>${esc(size(a.size))}</dd><dt>Digest</dt><dd>${esc(a.digest)}</dd><dt>Media type</dt><dd>${esc(a.media_type)}</dd></dl><a class="button small secondary" href="/v1/blobs/${enc(a.digest)}" download="${esc(name)}.wasm">Download ↓</a></article>`,
        )
        .join("");
      $("#interfaces").textContent = "Loading interface metadata…";
      const analyses = await Promise.all(
        m.artifacts.map(async (a) => {
          try {
            return {
              name: a.name,
              data: await api(`/v1/blobs/${enc(a.digest)}/component`),
            };
          } catch (e) {
            return e.status === 404 ? null : { name: a.name, error: e.message };
          }
        }),
      );
      $("#interfaces").innerHTML =
        analyses
          .filter(Boolean)
          .map((a) =>
            a.error
              ? `<p class="error">${esc(a.error)}</p>`
              : `<details open><summary>${esc(a.name)} · ${esc(a.data.world || a.data.package || a.data.kind)}</summary><p class="quiet">${a.data.imports.length} imports · ${a.data.exports.length} exports</p><pre class="code-panel">${esc(a.data.wit)}</pre></details>`,
          )
          .join("") ||
        '<p class="quiet">No inspectable component interfaces are available for this release.</p>';
      if (session) {
        const namespace = await api(`/v1/namespaces/${enc(ns)}`);
        if (namespace.owner_username === session.username) {
          $("#release-admin").hidden = false;
          const b = $("#yank");
          b.textContent = data.record.yanked
            ? "Restore release"
            : "Yank release";
          b.addEventListener("click", async () => {
            b.disabled = true;
            try {
              await api(`${endpoint}/${enc(version)}/yank`, {
                method: data.record.yanked ? "DELETE" : "POST",
                json: {},
              });
              location.reload();
            } catch (e) {
              status("#yank-status", e.message, true);
              b.disabled = false;
            }
          });
        }
      }
    }
    copy("#copy-install", "#install-command");
  }
  function packageOverview(data, endpoint, ns, name) {
    $('#package-namespace').textContent = ns;
    $('#package-name').textContent = name;
    $('#package-visibility').textContent = data.visibility === 'private' ? 'Private' : 'Public';
    $('#package-updated').textContent = `Updated ${date(data.updated_at)}`;
    $('#version-count').textContent = data.versions.length;
    renderMarkdown(data.overview, $('#overview-content'));
    const tabs = [$('#overview-tab'), $('#versions-tab')];
    function selectTab(selected) {
      tabs.forEach(tab => {
        const active = tab === selected;
        tab.setAttribute('aria-selected', String(active));
        tab.tabIndex = active ? 0 : -1;
        document.getElementById(tab.getAttribute('aria-controls')).hidden = !active;
      });
    }
    tabs.forEach(tab => {
      tab.addEventListener('click', () => selectTab(tab));
      tab.addEventListener('keydown', event => {
        if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
        event.preventDefault();
        const next = event.key === 'Home' ? tabs[0] : event.key === 'End' ? tabs[1] : tabs.find(t => t !== tab);
        selectTab(next); next.focus();
      });
    });
    const latest = data.latest_release;
    if (latest) {
      const m = latest.manifest;
      $('#latest-version').textContent = m.version;
      $('#latest-version').href = $('#inspect-release').href = url(ns, name, m.version);
      const fields = [
        ['Content type', [...new Set(m.artifacts.map(a => a.kind === 'component' ? 'Wasm component' : 'Core module'))].join(', ')],
        ['Artifacts', String(m.artifacts.length)],
        ['Total size', size(m.artifacts.reduce((sum, a) => sum + a.size, 0))],
        ['Published', date(latest.record.created_at)],
        ['License', m.license || 'Not specified'],
        ['Manifest digest', latest.record.manifest_digest],
      ];
      $('#release-summary').innerHTML = fields.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('');
    } else {
      $('#latest-version').textContent = 'None';
      $('#release-summary').textContent = 'All releases are yanked. Exact versions remain available in Versions.';
      $('#inspect-release').hidden = true;
    }
    if (session?.username !== data.owner_username) return;
    const edit = $('#edit-overview'), editor = $('#overview-form'), content = $('#overview-content');
    const write = markdownEditor($('#overview-editor'));
    function editing(active) {
      editor.hidden = !active; content.hidden = active; edit.hidden = active;
      if (active) { $('#overview-markdown').value = data.overview; write(); $('#overview-markdown').focus(); }
    }
    edit.hidden = false;
    edit.addEventListener('click', () => { status('#overview-status', ''); editing(true); });
    $('#cancel-overview').addEventListener('click', () => { editing(false); edit.focus(); });
    form('#overview-form', '#overview-status', async values => {
      const result = await api(`${endpoint}/overview`, { method: 'PUT', json: {
        overview: validateOverview(String(values.get('overview'))), revision: data.overview_revision,
      } });
      Object.assign(data, result);
      renderMarkdown(data.overview, content);
      editing(false); edit.focus();
      status('#page-status', 'Overview saved.');
    });
  }
  async function start() {
    try {
      localStorage.removeItem("wasmd_registry_token");
    } catch {}
    document.querySelectorAll(".topbar nav a").forEach((a) => {
      if (a.pathname === location.pathname)
        a.setAttribute("aria-current", "page");
    });
    if (page === "register" || page === "login") auth();
    await loadSession();
    try {
      if (page === "home" || page === "explore") await explore();
      else if (page === "account") await account();
      else if (page === "publish") await publish();
      else if (page === "package" || page === "release") await details();
    } catch (e) {
      status("#page-status", e.message, true);
    }
  }
  start();
})();
