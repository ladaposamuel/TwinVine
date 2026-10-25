const status = document.querySelector("#status");
const manifests = document.querySelector("#manifests");
const send = document.querySelector("#send");
const port = 8765;
let selectedUrl = "";

function ago(time) {
  const seconds = Math.max(0, Math.round((Date.now() - time) / 1000));
  if (seconds < 10) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  return new Date(time).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
}

function paintSelection() {
  for (const button of manifests.querySelectorAll(".item")) {
    button.classList.toggle("selected", button.dataset.url === selectedUrl);
  }
}

async function refresh() {
  try {
    const health = await fetch(`http://127.0.0.1:${port}/health`);
    status.textContent = health.ok
      ? "HellYes is open. The video in the open dialog is listed first."
      : "HellYes did not answer. Open it with uv run python gui.py first.";
  } catch (error) {
    status.textContent = "HellYes is not running. Open it with uv run python gui.py, from the TwinVine folder.";
  }

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const listed = await chrome.runtime.sendMessage({ type: "list" });
  const items = (listed && listed.items ? listed.items : []).filter((item) => item.kind === "mpd");
  items.sort((left, right) => {
    const score = (item) => (item.tabId === tab?.id ? 0 : 2) + (item.inModal ? 0 : 1);
    return score(left) - score(right) || right.time - left.time;
  });
  manifests.replaceChildren();
  if (!items.length) {
    const empty = document.createElement("p");
    empty.textContent = "No manifest yet. Open the video and press play.";
    manifests.append(empty);
    send.disabled = true;
    selectedUrl = "";
    return;
  }
  send.disabled = false;
  const featured = items.find((item) => item.tabId === tab?.id && item.inModal) || items[0];
  selectedUrl = featured.url;
  for (const item of items) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "item";
    button.dataset.url = item.url;
    const where = item.inModal ? "In the open dialog" : "On the page";
    const place = item.tabId === tab?.id ? "this tab" : "another tab";
    const ready = item.hasBody ? "response captured" : "url only";
    const file = item.file && item.file !== item.title ? item.file : "";
    const badge = item.url === featured.url && item.inModal ? `<span class="badge">Video in the modal</span>` : "";
    button.innerHTML = `${badge}<strong></strong><span class="detail"></span><span class="meta"></span>`;
    button.querySelector("strong").textContent = item.title || item.url;
    button.querySelector(".detail").textContent = file;
    button.querySelector(".meta").textContent = `${where} · ${place} · ${ago(item.time)} · ${ready}`;
    if (!file) button.querySelector(".detail").remove();
    button.addEventListener("click", () => {
      selectedUrl = item.url;
      paintSelection();
    });
    manifests.append(button);
  }
  paintSelection();
}

send.addEventListener("click", async () => {
  if (!selectedUrl) return;
  send.disabled = true;
  status.textContent = "Sending…";
  const result = await chrome.runtime.sendMessage({ type: "send", url: selectedUrl, port });
  status.textContent = result && result.ok ? "Sent. Go back to HellYes and click Get Keys." : (result && result.error) || "Send failed.";
  send.disabled = false;
});

refresh();
