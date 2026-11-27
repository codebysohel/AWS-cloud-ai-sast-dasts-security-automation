// app.js -- talks to the local Flask backend
const API = "http://localhost:5000";

const $ = (id) => document.getElementById(id);
const BUCKET_RE = /^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$/;

function creds() {
  return {
    accessKeyId: $("accessKeyId").value.trim(),
    secretAccessKey: $("secretAccessKey").value.trim(),
    region: $("region").value.trim(),
  };
}

function setErr(field, msg) {
  const el = document.querySelector(`.err[data-for="${field}"]`);
  if (el) el.textContent = msg || "";
}

function clearErrs() {
  document.querySelectorAll(".err").forEach((e) => (e.textContent = ""));
}

function toast(msg, ok = true) {
  const t = $("toast");
  t.textContent = msg;
  t.className = "toast " + (ok ? "ok" : "bad");
  setTimeout(() => (t.className = "toast hidden"), 4000);
}

function loading(btn, on, label) {
  btn.disabled = on;
  if (on) {
    btn.dataset.text = btn.textContent;
    btn.textContent = label || "Working";
    btn.classList.add("loading");
  } else {
    btn.textContent = btn.dataset.text || btn.textContent;
    btn.classList.remove("loading");
  }
}

// ---- validation -----------------------------------------------------------
function validateConnFields() {
  clearErrs();
  const c = creds();
  let ok = true;
  if (!c.accessKeyId) { setErr("accessKeyId", "Required"); ok = false; }
  if (!c.secretAccessKey) { setErr("secretAccessKey", "Required"); ok = false; }
  if (!c.region) { setErr("region", "Required"); ok = false; }
  return ok;
}

function validateAll() {
  if (!validateConnFields()) return false;
  const bucket = $("bucketName").value.trim();
  if (!bucket) { setErr("bucketName", "Required"); return false; }
  if (!BUCKET_RE.test(bucket)) {
    setErr("bucketName", "3-63 chars: a-z, 0-9, dot, hyphen; start/end alphanumeric");
    return false;
  }
  return true;
}

async function postJSON(path, body) {
  const res = await fetch(API + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return res.json();
}

// ---- actions --------------------------------------------------------------
$("btnValidate").addEventListener("click", async () => {
  if (!validateConnFields()) return;
  const btn = $("btnValidate");
  loading(btn, true, "Validating");
  $("identity").textContent = "";
  try {
    const r = await postJSON("/api/validate", creds());
    if (r.success) {
      $("identity").textContent = "\u2714 " + r.message;
      toast("Credentials valid");
    } else {
      $("identity").textContent = "";
      toast(r.message, false);
    }
  } catch (e) {
    toast("Cannot reach backend at " + API + " - is it running?", false);
  } finally {
    loading(btn, false);
  }
});

$("mainForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  if (!validateAll()) return;
  const btn = $("btnApply");
  loading(btn, true, "Applying");
  try {
    const body = {
      ...creds(),
      bucketName: $("bucketName").value.trim(),
      iamUser: $("iamUser").value.trim(),
      existingKeyArn: $("existingKeyArn").value.trim(),
      createUserIfMissing: $("createUserIfMissing").checked,
    };
    const r = await postJSON("/api/apply", body);
    renderResult(r);
    if (r.keyArn) $("existingKeyArn").value = r.keyArn; // reuse on re-run/upload
    toast(r.success ? "Encryption applied" : "Applied with errors", r.success);
  } catch (e) {
    toast("Cannot reach backend at " + API + " - is it running?", false);
  } finally {
    loading(btn, false);
  }
});

$("btnVerify").addEventListener("click", async () => {
  if (!validateAll()) return;
  const btn = $("btnVerify");
  loading(btn, true, "Verifying");
  try {
    const body = { ...creds(), bucketName: $("bucketName").value.trim() };
    const r = await postJSON("/api/verify", body);
    if (r.message && !r.checks) { toast(r.message, false); return; }
    renderChecks(r);
    toast(r.success ? "All checks passed" : "Some checks failed", r.success);
  } catch (e) {
    toast("Cannot reach backend at " + API + " - is it running?", false);
  } finally {
    loading(btn, false);
  }
});

$("btnUpload").addEventListener("click", async () => {
  if (!validateAll()) return;
  const file = $("fileInput").files[0];
  if (!file) { toast("Choose a file first", false); return; }
  const btn = $("btnUpload");
  loading(btn, true, "Uploading");
  try {
    const fd = new FormData();
    const c = creds();
    fd.append("accessKeyId", c.accessKeyId);
    fd.append("secretAccessKey", c.secretAccessKey);
    fd.append("region", c.region);
    fd.append("bucketName", $("bucketName").value.trim());
    fd.append("keyArn", $("existingKeyArn").value.trim());
    fd.append("file", file);
    const res = await fetch(API + "/api/upload", { method: "POST", body: fd });
    const r = await res.json();
    const out = $("uploadOut");
    if (r.result) {
      out.textContent =
        "key:                 " + r.result.key + "\n" +
        "size (bytes):        " + r.result.size + "\n" +
        "serverSideEncryption:" + r.result.serverSideEncryption + "\n" +
        "kmsKeyId:            " + (r.result.kmsKeyId || "-") + "\n" +
        "encryptedAtRest:     " + r.result.encryptedAtRest;
    } else {
      out.textContent = r.message || "Upload failed.";
    }
    toast(r.success ? "Uploaded & encrypted at rest" : (r.message || "Upload failed"), r.success);
  } catch (e) {
    toast("Cannot reach backend at " + API + " - is it running?", false);
  } finally {
    loading(btn, false);
  }
});

// ---- rendering ------------------------------------------------------------
function renderResult(r) {
  $("results").classList.remove("hidden");
  const msg = $("resultMsg");
  msg.className = "result-msg " + (r.success ? "ok" : "bad");
  msg.textContent = r.message || (r.success ? "Success" : "Failed");
  const list = $("stepList");
  list.innerHTML = "";
  (r.steps || []).forEach((s) => {
    const li = document.createElement("li");
    const ok = s.status === "success";
    li.innerHTML =
      `<span class="badge ${ok ? "ok" : "bad"}">${ok ? "PASS" : "FAIL"}</span>` +
      `<span><b>${s.name}</b> - ${escapeHtml(s.detail || "")}</span>`;
    list.appendChild(li);
  });
  $("keyOut").textContent = r.keyArn
    ? `account: ${r.account}\nregion:  ${r.region}\nbucket:  ${r.bucket}\nkeyArn:  ${r.keyArn}`
    : "";
}

function renderChecks(r) {
  $("results").classList.remove("hidden");
  const msg = $("resultMsg");
  msg.className = "result-msg " + (r.success ? "ok" : "bad");
  msg.textContent = r.success ? "Verification passed" : "Verification found issues";
  const list = $("stepList");
  list.innerHTML = "";
  Object.entries(r.checks || {}).forEach(([name, c]) => {
    const li = document.createElement("li");
    li.innerHTML =
      `<span class="badge ${c.ok ? "ok" : "bad"}">${c.ok ? "PASS" : "FAIL"}</span>` +
      `<span><b>${name}</b> - ${escapeHtml(c.detail || "")}</span>`;
    list.appendChild(li);
  });
  $("keyOut").textContent = `region: ${r.region}\nbucket: ${r.bucket}`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
