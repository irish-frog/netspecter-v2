(function () {
  function closeMenus(except) {
    document.querySelectorAll(".ns-menu-wrap.is-open").forEach((wrap) => {
      if (wrap === except) return;
      wrap.classList.remove("is-open");
      const trigger = wrap.querySelector(".ns-menu-trigger");
      if (trigger) trigger.setAttribute("aria-expanded", "false");
    });
  }

  function closeFloatingControls() {
    closeMenus();
    document.querySelectorAll(".ns-tools-wrap.is-open").forEach((item) => item.classList.remove("is-open"));
    document.querySelectorAll(".ns-confirm-backdrop.is-open").forEach((item) => {
      item.classList.remove("is-open");
      item.setAttribute("hidden", "");
    });
  }

  function openMenu(wrap) {
    closeMenus(wrap);
    wrap.classList.add("is-open");
    const trigger = wrap.querySelector(".ns-menu-trigger");
    const menu = wrap.querySelector(".ns-menu");
    if (trigger) trigger.setAttribute("aria-expanded", "true");
    if (!menu) return;

    const rect = menu.getBoundingClientRect();
    const viewportPadding = 8;
    if (rect.right > window.innerWidth - viewportPadding) {
      menu.style.right = "auto";
      menu.style.left = "0";
    } else {
      menu.style.right = "0";
      menu.style.left = "auto";
    }
  }

  function toggleMenu(trigger) {
    const wrap = trigger.closest(".ns-menu-wrap");
    if (!wrap) return;
    if (wrap.classList.contains("is-open")) {
      closeMenus();
    } else {
      openMenu(wrap);
    }
  }

  document.addEventListener("click", (event) => {
    const toolsTrigger = event.target.closest("[data-tools-trigger]");
    if (toolsTrigger) {
      event.preventDefault();
      const wrap = toolsTrigger.closest(".ns-tools-wrap");
      if (wrap) {
        document.querySelectorAll(".ns-tools-wrap.is-open").forEach((item) => {
          if (item !== wrap) item.classList.remove("is-open");
        });
        wrap.classList.toggle("is-open");
      }
      return;
    }

    const trigger = event.target.closest(".ns-menu-trigger");
    if (trigger) {
      event.preventDefault();
      toggleMenu(trigger);
      return;
    }

    if (!event.target.closest(".ns-menu-wrap")) {
      closeMenus();
    }
    if (!event.target.closest(".ns-tools-wrap")) {
      document.querySelectorAll(".ns-tools-wrap.is-open").forEach((item) => item.classList.remove("is-open"));
    }
  });

  document.addEventListener("keydown", (event) => {
    const trigger = event.target.closest(".ns-menu-trigger");
    if (trigger && (event.key === "Enter" || event.key === " ")) {
      event.preventDefault();
      toggleMenu(trigger);
      return;
    }

    if (event.key === "Escape") {
      closeFloatingControls();
    }
  });

  document.addEventListener("click", (event) => {
    const tab = event.target.closest("[data-drawer-tab]");
    const jump = event.target.closest("[data-drawer-tab-jump]");
    const targetTab = tab || jump;
    if (!targetTab) return;
    const root = targetTab.closest("[data-drawer-root]");
    if (!root) return;
    const name = targetTab.getAttribute("data-drawer-tab") || targetTab.getAttribute("data-drawer-tab-jump");
    root.querySelectorAll("[data-drawer-tab]").forEach((item) => item.classList.toggle("is-active", item.getAttribute("data-drawer-tab") === name));
    root.querySelectorAll("[data-drawer-panel]").forEach((panel) => {
      panel.classList.toggle("is-active", panel.getAttribute("data-drawer-panel") === name);
    });
  });

  document.addEventListener("click", (event) => {
    const trigger = event.target.closest("[data-confirm-target]");
    if (trigger) {
      event.preventDefault();
      const target = document.querySelector(trigger.getAttribute("data-confirm-target"));
      if (target) {
        target.removeAttribute("hidden");
        target.classList.add("is-open");
      }
      return;
    }
    if (event.target.matches("[data-confirm-close]")) {
      event.preventDefault();
      const backdrop = event.target.closest(".ns-confirm-backdrop");
      if (backdrop) {
        backdrop.classList.remove("is-open");
        backdrop.setAttribute("hidden", "");
      }
    }
  });

  function setupPagination(table) {
    if (table.__nsPager) table.__nsPager.remove();
    table.__nsPager = null;
    const pageSize = Number(table.getAttribute("data-page-size") || 12);
    const rows = Array.from(table.querySelectorAll("tbody tr"));
    if (rows.length <= pageSize) return;
    let page = 0;
    const pager = document.createElement("div");
    pager.className = "ns-pagination";
    table.__nsPager = pager;
    table.closest(".ns-table-shell")?.after(pager);

    function render() {
      const visibleRows = rows.filter((row) => row.getAttribute("data-filter-hidden") !== "1");
      const pages = Math.max(1, Math.ceil(visibleRows.length / pageSize));
      page = Math.min(page, pages - 1);
      rows.forEach((row) => {
        row.style.display = "none";
      });
      visibleRows.forEach((row, index) => {
        row.style.display = index >= page * pageSize && index < (page + 1) * pageSize ? "" : "none";
      });
      pager.innerHTML = "";
      if (visibleRows.length <= pageSize) return;
      const prev = document.createElement("button");
      prev.type = "button";
      prev.textContent = "<";
      prev.disabled = page === 0;
      prev.addEventListener("click", () => { page = Math.max(0, page - 1); render(); });
      pager.appendChild(prev);
      for (let index = 0; index < pages; index += 1) {
        if (pages > 6 && index > 2 && index < pages - 2 && Math.abs(index - page) > 1) {
          if (!pager.querySelector("[data-ellipsis]")) {
            const ellipsis = document.createElement("span");
            ellipsis.setAttribute("data-ellipsis", "1");
            ellipsis.textContent = "...";
            pager.appendChild(ellipsis);
          }
          continue;
        }
        const button = document.createElement("button");
        button.type = "button";
        button.textContent = String(index + 1);
        button.classList.toggle("is-active", index === page);
        button.addEventListener("click", () => { page = index; render(); });
        pager.appendChild(button);
      }
      const next = document.createElement("button");
      next.type = "button";
      next.textContent = ">";
      next.disabled = page >= pages - 1;
      next.addEventListener("click", () => { page = Math.min(pages - 1, page + 1); render(); });
      pager.appendChild(next);
    }

    render();
    table.__nsRenderPager = () => { page = 0; render(); };
  }

  function setupTableSearch(input) {
    const table = document.getElementById(input.getAttribute("data-table-search"));
    if (!table) return;
    const applyFilter = () => {
      const term = input.value.trim().toLowerCase();
      table.querySelectorAll("tbody tr").forEach((row) => {
        const haystack = (row.getAttribute("data-search") || row.textContent || "").toLowerCase();
        row.setAttribute("data-filter-hidden", term && !haystack.includes(term) ? "1" : "0");
      });
      if (table.__nsRenderPager) table.__nsRenderPager();
    };
    input.addEventListener("input", applyFilter);
    applyFilter();
  }

  function refreshTables() {
    document.querySelectorAll("table[data-page-size]").forEach(setupPagination);
    document.querySelectorAll("[data-table-search]").forEach(setupTableSearch);
  }

  refreshTables();
  window.NetSpecterUi = window.NetSpecterUi || {};
  window.NetSpecterUi.refreshTables = refreshTables;

  function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value || "-";
  }

  function setHref(id, href) {
    const el = document.getElementById(id);
    if (el) el.setAttribute("href", href);
  }

  function selectedDeviceIp() {
    return document.querySelector(".ns-device-row.is-selected")?.dataset.ip || "";
  }

  let deviceActivityChart = null;

  function activateDrawerTab(name) {
    const root = document.querySelector("[data-drawer-root]");
    if (!root || !name) return;
    root.querySelectorAll("[data-drawer-tab]").forEach((item) => item.classList.toggle("is-active", item.getAttribute("data-drawer-tab") === name));
    root.querySelectorAll("[data-drawer-panel]").forEach((panel) => {
      panel.classList.toggle("is-active", panel.getAttribute("data-drawer-panel") === name);
    });
  }

  function renderDrawerList(id, rows, emptyText, renderRow) {
    const el = document.getElementById(id);
    if (!el) return;
    if (!rows || !rows.length) {
      el.innerHTML = `<div class="ns-dashboard-empty">${emptyText}</div>`;
      return;
    }
    el.innerHTML = rows.map(renderRow).join("");
  }

  function esc(value) {
    return String(value || "").replace(/[&<>"']/g, (char) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      "\"": "&quot;",
      "'": "&#39;"
    }[char]));
  }

  async function fetchJsonOrThrow(url, options) {
    const response = await fetch(url, options || {});
    const contentType = response.headers.get("content-type") || "";
    if (!contentType.includes("application/json")) {
      const text = await response.text();
      throw new Error(`HTTP ${response.status}: ${text.slice(0, 160).replace(/\s+/g, " ")}`);
    }
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
    return data;
  }

  async function loadDeviceDrawerData(ip, period) {
    if (!ip) return;
    const range = period || document.querySelector("[data-device-range].is-active")?.getAttribute("data-device-range") || "1d";
    const historyType = document.getElementById("deviceHistoryType")?.value || "";
    const historyRange = document.getElementById("deviceHistoryRange")?.value || range;
    try {
      const data = await fetchJsonOrThrow(`/api/device/${encodeURIComponent(ip)}/drawer?period=${encodeURIComponent(range)}&history_type=${encodeURIComponent(historyType)}`, { cache: "no-store" });
      if (!data.ok) throw new Error(data.error || "Device data unavailable");
      const canvas = document.getElementById("deviceActivityChart");
      if (canvas && typeof Chart !== "undefined") {
        if (deviceActivityChart) deviceActivityChart.destroy();
        deviceActivityChart = new Chart(canvas, {
          type: "line",
          data: {
            labels: data.traffic.labels || [],
            datasets: [
              { label: "Download", data: data.traffic.downloaded || [], borderColor: "#18aaff", backgroundColor: "rgba(24,170,255,.12)", tension: .28, pointRadius: 0 },
              { label: "Upload", data: data.traffic.uploaded || [], borderColor: "#9c6cff", backgroundColor: "rgba(156,108,255,.12)", tension: .28, pointRadius: 0 }
            ]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            plugins: { legend: { labels: { color: "#a4b1c6", boxWidth: 10 } } },
            scales: {
              x: { ticks: { color: "#8ea0b8", maxTicksLimit: 6 }, grid: { color: "rgba(148,163,184,.06)" } },
              y: { beginAtZero: true, ticks: { color: "#8ea0b8", maxTicksLimit: 5 }, grid: { color: "rgba(148,163,184,.10)" } }
            }
          }
        });
      }
      renderDrawerList("deviceTopApps", data.apps, "No application activity in this range.", (row) => `<div class="ns-drawer-list-row"><b>${esc(row.name || "Other")}</b><span>${Number(row.total || 0)} DNS hits</span></div>`);
      renderDrawerList("deviceTopDomains", data.domains, "No recent domains in this range.", (row) => `<div class="ns-drawer-list-row"><b>${esc(row.name || "-")}</b><span>${Number(row.total || 0)} hits</span></div>`);
      renderDrawerList("deviceHistoryList", data.history, `No ${esc(historyRange)} history events found.`, (row) => `<a class="ns-timeline-row" href="${esc(row.href || "#")}"><span>${esc(row.ts || "-")}</span><b>${esc(row.title || row.type)}</b><em>${esc(row.detail || "")}</em></a>`);
      const alertRows = [
        ...(data.alerts.ids || []).map((row) => ({ href: row.href, title: `IDS P${row.severity}: ${row.signature}`, meta: row.ts })),
        ...(data.alerts.anomalies || []).map((row) => ({ href: row.href, title: `Anomaly: ${row.rule}`, meta: `${row.severity} / ${row.status}` })),
        ...(data.alerts.incidents || []).map((row) => ({ href: row.href, title: `Incident: ${row.title}`, meta: `${row.severity} / ${row.status}` }))
      ];
      renderDrawerList("deviceAlertsList", alertRows, "No related IDS, anomaly or incident records.", (row) => `<a class="ns-drawer-list-row" href="${esc(row.href)}"><b>${esc(row.title)}</b><span>${esc(row.meta || "")}</span></a>`);
    } catch (error) {
      renderDrawerList("deviceHistoryList", [{ title: "Device drawer data failed", detail: String(error), ts: "" }], "Device data unavailable.", (row) => `<div class="ns-timeline-row"><b>${esc(row.title)}</b><em>${esc(row.detail)}</em></div>`);
    }
  }

  function setDeviceDrawerFromRow(row) {
    if (!row) return;
    document.querySelectorAll(".ns-device-row.is-selected").forEach((item) => item.classList.remove("is-selected"));
    row.classList.add("is-selected");

    const data = row.dataset;
    const ip = data.ip || "";
    const encodedIp = encodeURIComponent(ip);
    const online = (data.online || "").toLowerCase() === "online";
    const ignored = data.ignored === "1";
    setText("deviceDrawerName", data.name || ip);
    setText("deviceDrawerIp", ip);
    setText("deviceDrawerMac", data.mac);
    setText("deviceDrawerType", data.type);
    setText("deviceDrawerVendor", data.vendor);
    setText("deviceDrawerStatus", data.status);
    setText("deviceDrawerFirst", data.first);
    setText("deviceDrawerLast", data.last);
    setText("deviceDrawerTotal", data.total);
    setText("deviceDrawerDown", data.down);
    setText("deviceDrawerUp", data.up);
    setText("deviceConfirmIp", ip);

    const labelInput = document.getElementById("deviceLabelInput");
    if (labelInput) labelInput.value = data.name || ip;

    const onlineChip = document.getElementById("deviceDrawerOnline");
    if (onlineChip) {
      onlineChip.textContent = online ? "Online" : "Offline";
      onlineChip.className = `ns-chip ns-chip--${online ? "online" : "offline"}`;
    }

    const ignoredChip = document.getElementById("deviceDrawerIgnored");
    if (ignoredChip) ignoredChip.style.display = ignored ? "inline-flex" : "none";
    setText("deviceIgnoreMenuText", ignored ? "Unignore device" : "Ignore device");
    setText("deviceIgnoreTitle", ignored ? "Unignore" : "Ignore");
    const ignoreValue = document.getElementById("deviceIgnoreValue");
    if (ignoreValue) ignoreValue.value = ignored ? "0" : "1";
    const ignoreButton = document.getElementById("deviceIgnoreButton");
    if (ignoreButton) ignoreButton.textContent = `${ignored ? "Unignore" : "Ignore"} ${ip}`;

    ["deviceDrawerTotal", "deviceDrawerDown", "deviceDrawerUp"].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.setAttribute("data-live-ip", ip);
    });

    setHref("deviceToolPing", `/ping/${encodedIp}`);
    setHref("deviceToolScan", `/scan/${encodedIp}`);
    setHref("deviceDrawerTimeline", `/device/${encodedIp}`);
    setHref("deviceDrawerAlertsLink", `/ids-alerts?device=${encodedIp}`);

    const labelForm = document.getElementById("deviceLabelForm");
    if (labelForm) labelForm.setAttribute("action", `/device/${encodedIp}/label`);
    const ignoreForm = document.getElementById("deviceIgnoreForm");
    if (ignoreForm) ignoreForm.setAttribute("action", `/device/${encodedIp}/ignore`);
    const form = document.getElementById("deviceBlockForm");
    if (form) form.setAttribute("action", `/device/pause/${encodedIp}`);
    const button = document.getElementById("deviceConfirmButton");
    if (button) button.textContent = `Block ${ip}`;

    const result = document.getElementById("deviceToolResult");
    if (result) {
      result.className = "ns-tool-result";
      result.textContent = "Select DNS lookup from Tools to resolve this device.";
    }
    loadDeviceDrawerData(ip);
  }

  document.addEventListener("click", (event) => {
    const row = event.target.closest(".ns-device-row");
    if (!row || event.target.closest("a, button, input, select, form, details, summary")) return;
    setDeviceDrawerFromRow(row);
  });

  document.addEventListener("click", (event) => {
    const range = event.target.closest("[data-device-range]");
    if (!range) return;
    document.querySelectorAll("[data-device-range]").forEach((item) => item.classList.toggle("is-active", item === range));
    loadDeviceDrawerData(selectedDeviceIp(), range.getAttribute("data-device-range"));
  });

  document.addEventListener("click", (event) => {
    if (!event.target.closest("[data-device-history-refresh]")) return;
    loadDeviceDrawerData(selectedDeviceIp(), document.getElementById("deviceHistoryRange")?.value || "1d");
  });

  const initialDeviceRow = document.querySelector(".ns-device-row.is-selected");
  if (initialDeviceRow) {
    setDeviceDrawerFromRow(initialDeviceRow);
    const params = new URLSearchParams(window.location.search);
    if (params.get("tab")) activateDrawerTab(params.get("tab"));
  }

  document.addEventListener("click", async (event) => {
    const trigger = event.target.closest("[data-device-dns-lookup]");
    if (!trigger) return;
    event.preventDefault();
    const ip = selectedDeviceIp();
    const result = document.getElementById("deviceToolResult");
    const form = document.getElementById("deviceLabelForm");
    if (!ip || !result || !form) return;
    result.className = "ns-tool-result";
    result.textContent = `Looking up ${ip}...`;
    try {
      const data = await fetchJsonOrThrow(`/api/device/${encodeURIComponent(ip)}/dns-lookup`, {
        method: "POST",
        body: new FormData(form),
        cache: "no-store"
      });
      if (data.ok) {
        const aliases = (data.aliases || []).length ? ` Aliases: ${data.aliases.join(", ")}` : "";
        result.className = "ns-tool-result is-ok";
        result.textContent = `Reverse DNS: ${data.hostname || "-"}${aliases}`;
      } else {
        result.className = "ns-tool-result is-error";
        result.textContent = `DNS lookup failed: ${data.error || "No reverse DNS result."}`;
      }
    } catch (error) {
      result.className = "ns-tool-result is-error";
      result.textContent = `DNS lookup failed: ${error}`;
    }
  });

  document.addEventListener("submit", async (event) => {
    const form = event.target.closest("#deviceLabelForm, #deviceIgnoreForm");
    if (!form) return;
    event.preventDefault();
    try {
      const data = await fetchJsonOrThrow(form.action, { method: "POST", body: new FormData(form), cache: "no-store" });
      if (!data.ok) throw new Error(data.error || "Action failed");
      window.location.reload();
    } catch (error) {
      const result = document.getElementById("deviceToolResult");
      if (result) {
        result.className = "ns-tool-result is-error";
        result.textContent = String(error);
      }
    }
  });

  const sidebar = document.getElementById("siteSidebar");
  const sidebarButton = document.querySelector(".ns-mobile-menu-button");
  const sidebarNav = document.querySelector(".ns-sidebar__nav");
  const sidebarScrollKey = "netspecter.sidebar.scrollTop";

  function setSidebar(open) {
    document.body.classList.toggle("ns-sidebar-open", open);
    if (sidebarButton) {
      sidebarButton.setAttribute("aria-expanded", open ? "true" : "false");
      sidebarButton.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
    }
  }

  if (sidebar && sidebarButton) {
    if (sidebarNav) {
      const savedScroll = Number(window.sessionStorage.getItem(sidebarScrollKey) || 0);
      if (savedScroll > 0) {
        requestAnimationFrame(() => {
          sidebarNav.scrollTop = savedScroll;
        });
      }

      sidebarNav.addEventListener("scroll", () => {
        window.sessionStorage.setItem(sidebarScrollKey, String(sidebarNav.scrollTop));
      }, { passive: true });
    }

    sidebarButton.addEventListener("click", () => {
      setSidebar(!document.body.classList.contains("ns-sidebar-open"));
    });

    document.addEventListener("click", (event) => {
      if (event.target.closest(".ns-mobile-menu-button")) return;
      if (event.target.closest("[data-sidebar-close]")) {
        setSidebar(false);
        return;
      }
      if (document.body.classList.contains("ns-sidebar-open") && !event.target.closest("#siteSidebar")) {
        setSidebar(false);
      }
    });

    sidebar.addEventListener("click", (event) => {
      const link = event.target.closest("a");
      if (link && sidebarNav) {
        window.sessionStorage.setItem(sidebarScrollKey, String(sidebarNav.scrollTop));
      }
      if (link) setSidebar(false);
    });

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") setSidebar(false);
    });
  }
})();
