// IRLid signing (ECDSA P-256) - requires WebCrypto (secure context)

(function () {
  if (!window.crypto || !window.crypto.subtle) {
    // Throwing makes it obvious in console AND our pages will catch and alert the message.
    throw new Error(
      "Secure crypto unavailable.\n\n" +
      "This feature requires WebCrypto, which is usually only available on HTTPS or localhost.\n\n" +
      "Fix:\n" +
      "• Use GitHub Pages (HTTPS) OR\n" +
      "• Test on localhost OR\n" +
      "• (Dev only) enable Chrome flag: Insecure origins treated as secure for this URL."
    );
  }
})();

function b64urlEncode(bytes) {
  const b64 = btoa(String.fromCharCode(...bytes));
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

function canonical(obj) {
  const keys = Object.keys(obj).sort();
  const o = {};
  for (const k of keys) o[k] = obj[k];
  return JSON.stringify(o);
}

async function sha256Bytes(str) {
  const enc = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest("SHA-256", enc);
  return new Uint8Array(hash);
}

async function ensureKeys() {
  if (localStorage.getItem("irlid_priv_jwk") && localStorage.getItem("irlid_pub_jwk")) return;

  const kp = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );

  const privJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const pubJwk  = await crypto.subtle.exportKey("jwk", kp.publicKey);

  localStorage.setItem("irlid_priv_jwk", JSON.stringify(privJwk));
  localStorage.setItem("irlid_pub_jwk", JSON.stringify(pubJwk));
}

async function getPublicJwk() {
  await ensureKeys();
  return JSON.parse(localStorage.getItem("irlid_pub_jwk"));
}

async function getPrivateKey() {
  await ensureKeys();
  const privJwk = JSON.parse(localStorage.getItem("irlid_priv_jwk"));
  return crypto.subtle.importKey(
    "jwk",
    privJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign"]
  );
}

async function importPublicKey(pubJwk) {
  return crypto.subtle.importKey(
    "jwk",
    pubJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );
}

async function signMid(midB64url) {
  const priv = await getPrivateKey();
  const midBytes = b64urlDecode(midB64url);

  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    priv,
    midBytes
  );

  return b64urlEncode(new Uint8Array(sig));
}

async function verifySig(midB64url, sigB64url, pubJwk) {
  const pub = await importPublicKey(pubJwk);
  const midBytes = b64urlDecode(midB64url);
  const sigBytes = b64urlDecode(sigB64url);

  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    pub,
    sigBytes,
    midBytes
  );
}

async function pubKeyId(pubJwk) {
  const s = `${pubJwk.kty}.${pubJwk.crv}.${pubJwk.x}.${pubJwk.y}`;
  const h = await sha256Bytes(s);
  return b64urlEncode(h).slice(0, 18);
}
