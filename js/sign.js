// IRLid signing (ECDSA P-256) - requires WebCrypto (secure context)
//  Deploy 67

(function () {
  if (!window.crypto || !window.crypto.subtle) {
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
    false,
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

/* =========================================================
   Added helpers for mutual validation / consistent signing
   (No backend; used by application.html and receipt.html)
   ========================================================= */

async function hashPayloadToB64url(payloadObj) {
  const payloadBytes = new TextEncoder().encode(JSON.stringify(payloadObj));
  const hashBuf = await crypto.subtle.digest("SHA-256", payloadBytes);
  return b64urlEncode(new Uint8Array(hashBuf));
}

async function signHashB64url(hashB64url) {
  // Signs the hash bytes directly
  // Uses ECDSA P-256 with SHA-256.
  const priv = await getPrivateKey();
  const hashBytes = b64urlDecode(hashB64url);

  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    priv,
    hashBytes
  );

  return b64urlEncode(new Uint8Array(sig));
}

/* =========================================================
   IRLid handshake helpers (static, no backend)
   - Encode/decode b64url JSON
   - Create signed "response" object for a given HELLO
   - Validate a scanned response against HELLO + optional self response
   ========================================================= */

function irlidEncodeJsonToB64url(obj){
  const bytes = new TextEncoder().encode(JSON.stringify(obj));
  return b64urlEncode(bytes);
}

function irlidDecodeB64urlJson(b64url){
  const bytes = b64urlDecode(String(b64url || ""));
  const txt = new TextDecoder().decode(bytes);
  return JSON.parse(txt);
}

async function irlidHelloHashB64url(helloObj){
  // Deterministic hash of the original HELLO object as encoded by index.html
  const bytes = new TextEncoder().encode(JSON.stringify(helloObj));
  const hashBuf = await crypto.subtle.digest("SHA-256", bytes);
  return b64urlEncode(new Uint8Array(hashBuf));
}

function irlidHaversineMeters(a, b){
  const R = 6371000;
  const toRad = (d) => d * Math.PI / 180;
  const lat1 = toRad(a.lat), lon1 = toRad(a.lon);
  const lat2 = toRad(b.lat), lon2 = toRad(b.lon);
  const dLat = lat2 - lat1;
  const dLon = lon2 - lon1;
  const s =
    Math.sin(dLat/2) * Math.sin(dLat/2) +
    Math.cos(lat1) * Math.cos(lat2) *
    Math.sin(dLon/2) * Math.sin(dLon/2);
  const c = 2 * Math.atan2(Math.sqrt(s), Math.sqrt(1-s));
  return R * c;
}

function irlidGetPosition(opts){
  return new Promise((resolve, reject) => {
    if (!navigator.geolocation) {
      reject(new Error("Geolocation unavailable."));
      return;
    }
    navigator.geolocation.getCurrentPosition(resolve, (err) => {
      reject(new Error(err && err.message ? err.message : "Geolocation error."));
    }, opts);
  });
}


async function makeSignedHelloAsync(opts){
  // Creates a HELLO object that already contains a signed, replay-resistant "offer"
  // so the other party can verify you immediately (2-scan handshake).
  const pos = await irlidGetPosition({
    enableHighAccuracy: true,
    maximumAge: 0,
    timeout: 12000
  });

  const lat = Number(pos.coords.latitude);
  const lon = Number(pos.coords.longitude);
  const acc = Number(pos.coords.accuracy || 0);

  if (!Number.isFinite(lat) || !Number.isFinite(lon)) {
    throw new Error("Invalid geolocation coordinates.");
  }

  const ts = Math.floor(Date.now() / 1000);
  const nonceA = crypto.getRandomValues(new Uint32Array(1))[0];

  // Offer payload is what gets hashed+signed.
  // Keep fields tight + deterministic ordering.
  const offerPayload = {
    v: 1,
    type: "offerPayload",
    lat,
    lon,
    acc,
    ts,
    nonce: nonceA
  };

  const pub = await getPublicJwk();
  const offerHash = await hashPayloadToB64url(offerPayload);
  const offerSig = await signHashB64url(offerHash);

  const hello = {
    v: 2,
    type: "hello",
    pub,
    nonce: nonceA,
    ts,
    offer: {
      payload: offerPayload,
      hash: offerHash,
      sig: offerSig
    }
  };

  return hello;
}

async function verifyHelloOfferAsync(helloObj, opts){
  const tsTolS = (opts && Number.isFinite(opts.tsTolS)) ? opts.tsTolS : 90;

  if (!helloObj || helloObj.type !== "hello") throw new Error("Invalid HELLO.");
  if (!helloObj.pub) throw new Error("Invalid HELLO (missing pub).");

  // Back-compat: unsigned HELLO v1
  if (!helloObj.offer) return { ok: true, mode: "unsigned-v1", offerHash: null };

  const offer = helloObj.offer;
  if (!offer || !offer.payload || !offer.hash || !offer.sig) {
    throw new Error("Invalid HELLO (bad offer structure).");
  }

  const computed = await hashPayloadToB64url(offer.payload);
  if (computed !== offer.hash) throw new Error("HELLO offer hash mismatch.");

  const sigOk = await verifySig(offer.hash, offer.sig, helloObj.pub);
  if (!sigOk) throw new Error("HELLO offer signature invalid.");

  const now = Math.floor(Date.now() / 1000);
  const ts = Number(offer.payload.ts);
  if (!Number.isFinite(ts)) throw new Error("HELLO offer timestamp missing.");
  const dt = Math.abs(now - ts);
  if (dt > tsTolS) throw new Error("HELLO offer timestamp outside tolerance (" + dt + "s > " + tsTolS + "s).");

  return { ok: true, mode: "signed-v2", offerHash: offer.hash };
}


async function makeReturnForHelloAsync(helloB64url, opts){
  if (!helloB64url) throw new Error("HELLO missing.");

  const tsTolS = (opts && Number.isFinite(opts.tsTolS)) ? opts.tsTolS : 90;

  const helloObj = irlidDecodeB64urlJson(helloB64url);
  if (!helloObj || helloObj.type !== "hello" || !helloObj.pub) {
    throw new Error("Invalid HELLO (bad structure).");
  }

  // If this HELLO contains a signed offer, verify it before proceeding.
  const offerInfo = await verifyHelloOfferAsync(helloObj, { tsTolS });

  const helloHash = await irlidHelloHashB64url(helloObj);

  const pos = await irlidGetPosition({
    enableHighAccuracy: true,
    maximumAge: 0,
    timeout: 12000
  });

  const lat = Number(pos.coords.latitude);
  const lon = Number(pos.coords.longitude);
  const acc = Number(pos.coords.accuracy || 0);

  if (!Number.isFinite(lat) || !Number.isFinite(lon)) {
    throw new Error("Invalid geolocation coordinates.");
  }

  const ts = Math.floor(Date.now() / 1000);
  const nonceB = crypto.getRandomValues(new Uint32Array(1))[0];

  // Accept payload (response) binds to the HELLO hash, and (if present) the signed offer hash.
  const payload = {
    v: 1,
    type: "payload",
    helloHash,
    offerHash: offerInfo.offerHash || undefined,
    lat,
    lon,
    acc,
    ts,
    nonce: nonceB
  };

  // Remove undefined to keep hashes stable
  if (payload.offerHash === undefined) delete payload.offerHash;

  const pub = await getPublicJwk();
  const hash = await hashPayloadToB64url(payload);
  const sig = await signHashB64url(hash);

  const resp = {
    v: 2,
    type: "response",
    payload,
    hash,
    sig,
    pub
  };

  // Cache for application.html to use in mutual verification
  window.__irlid_last_self_response = resp;

  return resp;
}



async function processScannedResponse(otherRespObj, opts){
  const helloB64url = opts && opts.hello ? opts.hello : null;
  const tsTolS = (opts && Number.isFinite(opts.tsTolS)) ? opts.tsTolS : 90;
  const distTolM = (opts && Number.isFinite(opts.distTolM)) ? opts.distTolM : 12;

  if (!helloB64url) throw new Error("HELLO missing for verification.");

  const helloObj = irlidDecodeB64urlJson(helloB64url);
  if (!helloObj || helloObj.type !== "hello") throw new Error("Invalid HELLO.");

  // Verify signed offer if present (v2). Back-compat allows unsigned v1.
  const offerInfo = await verifyHelloOfferAsync(helloObj, { tsTolS });

  const helloHash = await irlidHelloHashB64url(helloObj);

  const other = otherRespObj;
  if (!other || other.type !== "response" || !other.payload || !other.hash || !other.sig || !other.pub) {
    throw new Error("Invalid response (bad structure).");
  }

  const computed = await hashPayloadToB64url(other.payload);
  if (computed !== other.hash) throw new Error("Hash mismatch.");

  const sigOk = await verifySig(other.hash, other.sig, other.pub);
  if (!sigOk) throw new Error("Signature invalid.");

  // Binding checks:
  // - Always bind to the HELLO hash (legacy + new)
  if (!other.payload.helloHash || other.payload.helloHash !== helloHash) {
    throw new Error("HELLO binding mismatch.");
  }
  // - If HELLO has a signed offer, require the response to bind to that offer hash too.
  if (offerInfo.offerHash) {
    if (!other.payload.offerHash || other.payload.offerHash !== offerInfo.offerHash) {
      throw new Error("Offer binding mismatch.");
    }
  }

  // Timestamp tolerance (response freshness)
  const now = Math.floor(Date.now() / 1000);
  const ts = Number(other.payload.ts);
  if (!Number.isFinite(ts)) throw new Error("Response timestamp missing.");
  const dt = Math.abs(now - ts);
  if (dt > tsTolS) {
    throw new Error("Timestamp outside tolerance (" + dt + "s > " + tsTolS + "s).");
  }

  const self = window.__irlid_last_self_response || null;

  // Distance tolerance check (if self present)
  if (self && self.payload && Number.isFinite(self.payload.lat) && Number.isFinite(self.payload.lon)) {
    const d = irlidHaversineMeters(
      { lat: self.payload.lat, lon: self.payload.lon },
      { lat: other.payload.lat, lon: other.payload.lon }
    );
    if (d > distTolM) {
      throw new Error("Distance outside tolerance (" + Math.round(d) + "m > " + distTolM + "m).");
    }
  }

  const combined = {
    v: 2,
    type: "combined",
    tol: { dist_m: distTolM, ts_s: tsTolS },
    hello: helloObj,
    a: self,
    b: other
  };

  return { self, other, combined };
}
