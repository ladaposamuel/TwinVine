function clean(text) {
  return String(text || "").replace(/\s+/g, " ").trim().slice(0, 160);
}

function isVisible(element) {
  if (!(element instanceof Element)) return false;
  const style = getComputedStyle(element);
  if (style.display === "none" || style.visibility === "hidden" || Number(style.opacity) === 0) return false;
  const box = element.getBoundingClientRect();
  return box.width > 80 && box.height > 80 && box.bottom > 0 && box.right > 0;
}

function queryAllDeep(selector, root) {
  const found = [];
  const queue = [root];
  while (queue.length) {
    const node = queue.shift();
    if (!node || !node.querySelectorAll) continue;
    found.push(...node.querySelectorAll(selector));
    for (const element of node.querySelectorAll("*")) {
      if (element.shadowRoot) queue.push(element.shadowRoot);
    }
  }
  return found;
}

function closestDialog(element) {
  let node = element;
  while (node) {
    const className = typeof node.className === "string" ? node.className : node.getAttribute?.("class") || "";
    if (node instanceof Element && (node.matches("dialog[open], [role='dialog'], [aria-modal='true']") || /modal|dialog/i.test(className))) {
      return node;
    }
    const root = node.getRootNode && node.getRootNode();
    if (root instanceof ShadowRoot && !node.parentElement) {
      node = root.host;
      continue;
    }
    node = node.parentElement || null;
  }
  return null;
}

function headingText(root) {
  if (!(root instanceof Element)) return "";
  const labelledBy = root.getAttribute("aria-labelledby");
  if (labelledBy) {
    const text = labelledBy.split(/\s+/).map((id) => document.getElementById(id)?.textContent || "").join(" ");
    if (clean(text).length > 2) return clean(text);
  }
  const aria = clean(root.getAttribute("aria-label"));
  if (aria.length > 2 && !/^(close|play|pause|modal|dialog)$/i.test(aria)) return aria;
  const headings = root.querySelectorAll("h1, h2, h3, h4, [class*='title'], [data-title]");
  for (const heading of headings) {
    const text = clean(heading.textContent);
    if (text.length > 2 && !/^(close|play|pause|share|download)$/i.test(text)) return text;
  }
  return "";
}

function playbackContext(url) {
  const videos = queryAllDeep("video", document).filter(isVisible);
  const playing = videos.find((video) => !video.paused && video.readyState >= 2) || videos[videos.length - 1];
  const dialogs = queryAllDeep("dialog[open], [role='dialog'], [aria-modal='true']", document).filter(isVisible);
  const modal = (playing && closestDialog(playing)) || dialogs[dialogs.length - 1] || null;
  const label = headingText(modal) || clean(playing && (playing.getAttribute("title") || playing.getAttribute("aria-label"))) || clean(document.title);
  let inModal = Boolean(modal);
  if (modal && url) {
    const markup = modal.innerHTML || "";
    const needle = String(url).split("?")[0];
    if (needle && markup.includes(needle)) inModal = true;
  }
  return {
    label,
    pageTitle: clean(document.title),
    pageUrl: location.href,
    inModal,
  };
}

window.addEventListener("message", (event) => {
  if (event.source !== window || !event.data || event.data.source !== "hellyes-pair") return;
  const context = playbackContext(event.data.url);
  chrome.runtime.sendMessage({
    type: "page-capture",
    kind: event.data.kind,
    url: event.data.url,
    method: event.data.method || "GET",
    body: event.data.body || "",
    requestBody: event.data.requestBody || null,
    label: context.label,
    pageTitle: context.pageTitle,
    pageUrl: context.pageUrl,
    inModal: context.inModal,
  }).catch(() => {});
});
