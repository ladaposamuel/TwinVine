(() => {
  const SOURCE = "hellyes-pair";

  function classify(url, method) {
    const value = String(url || "").toLowerCase();
    if (value.includes(".mpd")) return "mpd";
    const verb = String(method || "GET").toUpperCase();
    if (verb === "POST" && /(license|licence|widevine|getlicense)/.test(value)) return "license";
    return null;
  }

  function absolute(url) {
    try {
      return new URL(url, location.href).href;
    } catch (error) {
      return String(url || "");
    }
  }

  function report(message) {
    window.postMessage({ source: SOURCE, ...message }, "*");
  }

  async function encodeBody(body) {
    if (body == null) return null;
    if (typeof body === "string") return { text: body };
    if (body instanceof URLSearchParams) return { text: body.toString() };
    if (body instanceof Blob) {
      const text = await body.text();
      return { text };
    }
    let bytes = null;
    if (body instanceof ArrayBuffer) bytes = new Uint8Array(body);
    else if (ArrayBuffer.isView(body)) bytes = new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
    if (!bytes) return { text: String(body) };
    let binary = "";
    for (let index = 0; index < bytes.length; index += 1) binary += String.fromCharCode(bytes[index]);
    const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    const printable = /^[\t\n\r\x20-\x7e]*$/.test(text);
    return { text: printable ? text : null, base64: btoa(binary) };
  }

  const originalFetch = window.fetch;
  window.fetch = async function (input, init) {
    const method = (init && init.method) || (input instanceof Request ? input.method : "GET");
    const rawUrl = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const url = absolute(rawUrl);
    const kind = classify(url, method);
    if (kind === "license") {
      try {
        let encoded = null;
        if (init && init.body != null && !(typeof ReadableStream !== "undefined" && init.body instanceof ReadableStream)) {
          encoded = await encodeBody(init.body);
        } else if (input instanceof Request) {
          encoded = await encodeBody(await input.clone().arrayBuffer());
        }
        report({ kind, url, method, requestBody: encoded });
      } catch (error) {
        report({ kind, url, method, requestBody: null });
      }
    }
    const response = await originalFetch.apply(this, arguments);
    if (kind === "mpd") {
      response.clone().text().then((body) => report({ kind, url: response.url || url, body })).catch(() => {});
    }
    return response;
  };

  const originalOpen = XMLHttpRequest.prototype.open;
  const originalSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method, url) {
    this.__hellyesMethod = method;
    this.__hellyesUrl = absolute(url);
    return originalOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function (body) {
    const url = this.__hellyesUrl;
    const method = this.__hellyesMethod || "GET";
    const kind = classify(url, method);
    if (kind === "license") {
      encodeBody(body).then((requestBody) => report({ kind, url, method, requestBody })).catch(() => {});
    }
    if (kind === "mpd") {
      this.addEventListener("load", function () {
        try {
          if (typeof this.responseText === "string" && this.responseText) {
            report({ kind, url: this.responseURL || url, body: this.responseText });
          }
        } catch (error) {
          // A non-text response has no responseText. The manifest request is text.
        }
      });
    }
    return originalSend.apply(this, arguments);
  };
})();
