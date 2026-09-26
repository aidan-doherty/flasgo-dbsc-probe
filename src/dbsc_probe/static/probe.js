"use strict";

const state = {
  status: null,
  gate: null,
  countdownTimer: null,
  restarting: false,
};

function el(id) {
  return document.getElementById(id);
}

function setText(id, value) {
  const node = el(id);
  if (node) node.textContent = value;
}

function toggleEmpty(id, isEmpty) {
  const node = el(id);
  if (node) node.classList.toggle("empty", isEmpty);
}

function setPre(id, value, emptyMessage) {
  const node = el(id);
  if (!node) return;
  const isEmpty = String(value).trim() === "";
  if (isEmpty && typeof emptyMessage === "string") {
    node.textContent = emptyMessage;
  } else {
    node.textContent = value;
  }
  node.classList.toggle("empty", isEmpty);
}

function render() {
  const s = state.status;
  const registered = s.registered;
  setText("probe-badge", "probe " + s.probe.slice(0, 8));
  setText("cookie-name", s.cookie.name);

  const regState = el("registration-state");
  const regDetail = el("registration-detail");
  if (s.corrupt) {
    regState.textContent = "Corrupt store state";
    regState.className = "state state-failed";
    regDetail.textContent = "The binding record exists but could not be read. Requests fail closed.";
  } else if (registered) {
    regState.textContent = "Registered";
    regState.className = "state state-registered";
    regDetail.textContent = "This probe is bound to a device key. The browser refreshes the cookie before it expires.";
  } else if (s.registration_header) {
    regState.textContent = "Registration offered";
    regState.className = "state state-offered";
    regDetail.textContent = "A DBSC-capable browser will register this probe automatically.";
  } else {
    regState.textContent = "Waiting…";
    regState.className = "state state-waiting";
    regDetail.textContent = "No registration offered yet. Reload the page.";
  }

  setPre("registration-header", s.registration_header, "No Secure-Session-Registration header seen yet.");
  if (registered && s.binding && s.binding.public_key_pem) {
    setPre("device-key", s.binding.public_key_pem, "");
  } else {
    setPre(
      "device-key",
      "",
      "No device key yet. A DBSC-capable browser binds a key to this probe when it registers."
    );
  }

  setText("cookie-present", s.cookie.present ? "yes" : "no");

  const exp = registered && s.binding ? s.binding.cookie_expires_at : null;
  const countdown = el("cookie-countdown");
  if (state.countdownTimer) {
    window.clearInterval(state.countdownTimer);
    state.countdownTimer = null;
  }
  if (exp !== null && s.cookie.present) {
    const tick = () => {
      const remaining = exp - Math.floor(Date.now() / 1000);
      countdown.textContent = Math.max(0, remaining) + "s";
    };
    tick();
    state.countdownTimer = window.setInterval(tick, 1000);
  } else if (exp !== null) {
    countdown.textContent = "cookie not on this request";
  } else {
    countdown.textContent = "–";
  }

  const matches = s.bound_cookie_matches;
  setText(
    "cookie-check",
    matches === null
      ? "No binding yet, so no enforcement check is made."
      : matches
        ? "Bound cookie verified: constant-time match with the stored value."
        : "Bound cookie missing or mismatched: a gated request would be terminated."
  );

  const jwt = s.registration_jwt;
  if (jwt && jwt.payload && jwt.header) {
    setPre("jwt-header", JSON.stringify(jwt.header, null, 2), "No registration JWT yet.");
    setPre("jwt-payload", JSON.stringify(jwt.payload, null, 2), "No registration JWT yet.");
    setPre("jwt-raw", jwt.raw, "");
  } else {
    setPre("jwt-header", "", "No registration JWT yet.");
    setPre("jwt-payload", "", "");
    setPre("jwt-raw", "", "");
  }

  if (s.instructions) {
    setPre("instructions", JSON.stringify(s.instructions, null, 2), "");
  } else {
    setPre("instructions", "", "The browser has not registered this probe.");
  }

  setPre("gate", renderGate(s), "Run the probe for the gate decision.");
  renderTimeline(s.timeline || []);
}

function renderGate(s) {
  const lines = [];
  if (s.corrupt) {
    lines.push("fail closed: present-but-unreadable binding record.");
  } else if (!s.registered) {
    lines.push("degraded to cookie auth: no binding, browser never registered.");
  }
  lines.push("bound_cookie_matches: " + String(s.bound_cookie_matches));
  if (state.gate) {
    lines.push("latest /check decision: " + JSON.stringify(state.gate, null, 2));
  }
  return lines.join("\n");
}

function renderTimeline(entries) {
  const ol = el("timeline");
  ol.textContent = "";
  for (const entry of entries) {
    const li = document.createElement("li");
    const ts = document.createElement("span");
    ts.className = "ts";
    ts.textContent = new Date(entry.time * 1000).toISOString().slice(11, 19);
    const evt = document.createElement("span");
    evt.className = "evt";
    evt.textContent = entry.event;
    li.append(ts, evt, " \u2014 " + entry.message);
    ol.append(li);
  }
}

function copyDiagnostic() {
  const payload = document.createElement("textarea");
  payload.value = JSON.stringify(state.status ?? {}, null, 2);
  document.body.append(payload);
  payload.select();
  try {
    document.execCommand("copy");
  } finally {
    payload.remove();
  }
}

async function start() {
  el("restart").addEventListener("click", async () => {
    if (state.restarting) return;
    state.restarting = true;
    document.getElementById("restart").disabled = true;
    await fetch("/restart", { method: "POST" });
    window.location.reload();
  });
  el("copy").addEventListener("click", copyDiagnostic);

  const poll = async () => {
    try {
      const statusResponse = await fetch("/status", { cache: "no-store" });
      if (!statusResponse.ok) throw new Error("status HTTP " + statusResponse.status);
      state.status = await statusResponse.json();
      const checkResponse = await fetch("/check", { cache: "no-store" });
      if (checkResponse.ok) {
        state.gate = await checkResponse.json();
      } else {
        state.gate = null;
      }
      render();
    } catch (error) {
      setText("registration-state", "Status poll failed: " + error.message);
    }
  };
  await poll();
  window.setInterval(poll, 1500);
}

document.addEventListener("DOMContentLoaded", start);