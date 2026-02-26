// /js/auth.js
// Passkey (WebAuthn) auth for IRLid (static, device-local)
// Deploy 1
(function () {
  "use strict";

  const LS_CRED_ID = "irlid_passkey_credId";
  const LS_LOGGED_IN = "irlid_passkey_logged_in";
  const LS_CREATED_AT = "irlid_passkey_createdAt";

  function b64urlEncode(bytes) {
    const bin = String.fromCharCode(...bytes);
    const b64 = btoa(bin);
    return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function b64urlDecode(str) {
    str = (str || "").replace(/-/g, "+").replace(/_/g, "/");
    while (str.length % 4) str += "=";
    const bin = atob(str);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function randomBytes(n) {
    const b = new Uint8Array(n);
    crypto.getRandomValues(b);
    return b;
  }

  function toArrayBuffer(u8) {
    return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
  }

  function hasWebAuthn() {
    return typeof window.PublicKeyCredential !== "undefined" &&
      typeof navigator.credentials !== "undefined" &&
      typeof navigator.credentials.create === "function" &&
      typeof navigator.credentials.get === "function";
  }

  function getCredId() {
    return localStorage.getItem(LS_CRED_ID) || "";
  }

  function setCredId(b64url) {
    localStorage.setItem(LS_CRED_ID, b64url);
    localStorage.setItem(LS_CREATED_AT, new Date().toISOString());
  }

  function setLoggedIn(v) {
    localStorage.setItem(LS_LOGGED_IN, v ? "1" : "0");
  }

  function isLoggedIn() {
    return localStorage.getItem(LS_LOGGED_IN) === "1";
  }

  async function platformAuthenticatorAvailable() {
    try {
      if (!hasWebAuthn()) return false;
      if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== "function") return false;
      return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch {
      return false;
    }
  }

  async function registerPasskey() {
    if (!window.isSecureContext) {
      throw new Error("WebAuthn requires a secure context (HTTPS).");
    }
    if (!hasWebAuthn()) {
      throw new Error("WebAuthn is not available in this browser.");
    }

    const rpId = location.hostname; // for GitHub Pages: bunhead.github.io
    const userId = randomBytes(16);

    const usePlatform = await platformAuthenticatorAvailable();

    const publicKey = {
      challenge: toArrayBuffer(randomBytes(32)),
      rp: {
        name: "IRLid",
        id: rpId
      },
      user: {
        id: toArrayBuffer(userId),
        name: "irlid-user",
        displayName: "IRLid User"
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },   // ES256
        { type: "public-key", alg: -257 }  // RS256 (fallback)
      ],
      timeout: 60000,
      attestation: "none",
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred"
      }
    };

    // Encourage FaceID/TouchID/etc when available, but don't hard-require it
    if (usePlatform) {
      publicKey.authenticatorSelection.authenticatorAttachment = "platform";
    }

    const cred = await navigator.credentials.create({ publicKey });
    if (!cred || !cred.rawId) {
      throw new Error("Passkey creation failed: no credential returned.");
    }

    const rawId = new Uint8Array(cred.rawId);
    const idB64url = b64urlEncode(rawId);

    setCredId(idB64url);
    setLoggedIn(true);

    return { credentialId: idB64url };
  }

  async function loginWithPasskey() {
    if (!window.isSecureContext) {
      throw new Error("WebAuthn requires a secure context (HTTPS).");
    }
    if (!hasWebAuthn()) {
      throw new Error("WebAuthn is not available in this browser.");
    }

    const credId = getCredId();
    if (!credId) {
      throw new Error("No passkey found on this device yet. Create one first.");
    }

    const allowId = b64urlDecode(credId);

    const publicKey = {
      challenge: toArrayBuffer(randomBytes(32)),
      timeout: 60000,
      userVerification: "preferred",
      allowCredentials: [
        {
          type: "public-key",
          id: toArrayBuffer(allowId)
        }
      ]
    };

    const assertion = await navigator.credentials.get({ publicKey });
    if (!assertion) {
      throw new Error("Login failed: no assertion returned.");
    }

    // Without a backend, we can't validate the signed challenge server-side.
    // However, the browser + authenticator still ensure that the user completed
    // a valid passkey ceremony for the stored credential ID.
    setLoggedIn(true);
    return true;
  }

  async function logout() {
    setLoggedIn(false);
  }

  async function getStatus() {
    const webauthnSupported = hasWebAuthn() && window.isSecureContext;
    const pa = await platformAuthenticatorAvailable();
    const credentialId = getCredId();
    return {
      webauthnSupported,
      platformAuthenticatorAvailable: pa,
      hasPasskey: !!credentialId,
      isLoggedIn: isLoggedIn(),
      credentialId
    };
  }

  window.IRLAuth = {
    registerPasskey,
    loginWithPasskey,
    logout,
    getStatus,
    isLoggedIn
  };
})();
