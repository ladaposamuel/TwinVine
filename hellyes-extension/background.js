const recent = [];
const headerMap = new Map();

function classify(url, method) {
  const value = String(url || "").toLowerCase();
  if (value.includes(".mpd")) return "mpd";
  const verb = String(method || "GET").toUpperCase();
  if (verb === "POST" && /(license|licence|widevine|getlicense)/.test(value)) return "license";
  return null;
}

function headerList(headers) {
  return (headers || [])
    .filter((header) => header && header.name && header.value)
    .map((header) => ({ name: header.name, value: header.value }));
}

function remember(entry) {
  const index = recent.findIndex((item) => item.kind === entry.kind && item.url === entry.url);
  const previous = index >= 0 ? recent[index] : null;
  if (index >= 0) recent.splice(index, 1);
  recent.unshift({
    label: "",
    pageTitle: "",
    pageUrl: "",
    inModal: false,
    tabId: null,
    ...(previous || {}),
    ...entry,
    label: entry.label || previous?.label || "",
    pageTitle: entry.pageTitle || previous?.pageTitle || "",
    pageUrl: entry.pageUrl || previous?.pageUrl || "",
    inModal: Object.prototype.hasOwnProperty.call(entry, "inModal") ? Boolean(entry.inModal) : Boolean(previous?.inModal),
    tabId: entry.tabId ?? previous?.tabId ?? null,
  });
  recent.splice(12);
}

function shortName(url) {
  try {
    const last = decodeURIComponent(new URL(url).pathname.split("/").filter(Boolean).pop() || "");
    const stem = last.replace(/\.mpd$/i, "");
    return stem.replace(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}-/i, "") || stem;
  } catch (error) {
    return "";
  }
}

function displayTitle(item) {
  const file = shortName(item.url);
  const label = String(item.label || "").trim();
  const page = String(item.pageTitle || "").trim();
  if (label && label !== page) return label;
  return file || page || item.url;
}

chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    const kind = classify(details.url, details.method);
    if (!kind) return;
    headerMap.set(details.url, headerList(details.requestHeaders));
    const tabId = details.tabId >= 0 ? details.tabId : null;
    if (!recent.some((item) => item.url === details.url && item.kind === kind)) {
      remember({
        kind,
        url: details.url,
        method: details.method,
        time: Date.now(),
        body: "",
        requestBody: null,
        headers: headerList(details.requestHeaders),
        tabId,
      });
    } else {
      const found = recent.find((item) => item.url === details.url && item.kind === kind);
      if (found) {
        found.headers = headerList(details.requestHeaders);
        if (tabId != null) found.tabId = tabId;
      }
    }
    if (tabId != null) {
      chrome.tabs.get(tabId).then((tab) => {
        const found = recent.find((item) => item.url === details.url && item.kind === kind);
        if (!found) return;
        if (!found.pageTitle) found.pageTitle = tab.title || "";
        if (!found.pageUrl) found.pageUrl = tab.url || "";
      }).catch(() => {});
    }
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders", "extraHeaders"]
);

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "page-capture") {
    const headers = headerMap.get(message.url) || [];
    remember({
      kind: message.kind,
      url: message.url,
      method: message.method,
      time: Date.now(),
      body: message.body || "",
      requestBody: message.requestBody,
      headers,
      tabId: _sender.tab?.id ?? null,
      label: message.label || "",
      pageTitle: message.pageTitle || _sender.tab?.title || "",
      pageUrl: message.pageUrl || _sender.tab?.url || "",
      inModal: Boolean(message.inModal),
    });
    sendResponse({ ok: true });
    return false;
  }
  if (message?.type === "list") {
    sendResponse({
      items: recent.map((item) => ({
        kind: item.kind,
        url: item.url,
        time: item.time,
        hasBody: Boolean(item.body),
        tabId: item.tabId,
        title: displayTitle(item),
        file: shortName(item.url),
        pageTitle: item.pageTitle || "",
        inModal: Boolean(item.inModal),
      })),
    });
    return false;
  }
  if (message?.type === "send") {
    sendToHellYes(message.url, message.port)
      .then((result) => sendResponse(result))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }
  return false;
});

function licenseFor(manifest) {
  const licenses = recent.filter((item) => item.kind === "license");
  const sameTab = licenses.filter((item) => manifest.tabId != null && item.tabId === manifest.tabId);
  const pool = sameTab.length ? sameTab : licenses;
  if (!pool.length) return null;
  const near = pool.filter((item) => item.time >= manifest.time - 1500);
  const ranked = (near.length ? near : pool).slice().sort((left, right) => {
    return Math.abs(left.time - manifest.time) - Math.abs(right.time - manifest.time);
  });
  return ranked[0];
}

async function cookieHeader(url) {
  const cookies = await chrome.cookies.getAll({ url });
  return cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join("; ");
}

async function headersFor(url, captured) {
  const headers = headerList(captured).filter((header) => header.name.toLowerCase() !== "cookie");
  const cookie = await cookieHeader(url);
  if (cookie) headers.push({ name: "Cookie", value: cookie });
  return headers;
}

async function sendToHellYes(mpdUrl, port) {
  const manifest = recent.find((item) => item.kind === "mpd" && item.url === mpdUrl) || recent.find((item) => item.kind === "mpd");
  if (!manifest) throw new Error("No manifest request has been seen. Reload the player and press play.");

  let body = manifest.body;
  if (!body) {
    const response = await fetch(manifest.url, { credentials: "include", cache: "no-store" });
    body = await response.text();
    if (!response.ok) throw new Error(`The manifest request returned ${response.status}. Play the video again and resend.`);
  }

  const license = licenseFor(manifest);
  let licensePayload = null;
  if (license) {
    licensePayload = {
      url: license.url,
      headers: await headersFor(license.url, license.headers),
      body_text: license.requestBody && license.requestBody.text ? license.requestBody.text : null,
    };
  }

  const targetPort = Number(port) || 8765;
  const response = await fetch(`http://127.0.0.1:${targetPort}/capture`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      mpd_url: manifest.url,
      mpd_body: body,
      title: displayTitle(manifest),
      headers: await headersFor(manifest.url, manifest.headers),
      license: licensePayload,
    }),
  });
  if (!response.ok) throw new Error(`HellYes refused the capture (${response.status}). Is the HellYes window open?`);
  return { ok: true };
}
