// js/qr.js deploy 9
// QR rendering tuned for weak cameras:
// - errorCorrectionLevel: "L" (lowest density)
// - larger margin/quiet zone
// - keeps fallback remote image
// Also keeps scanQR() helper.
// Deploy 15

(function () {
  "use strict";

  function elById(id) {
    const el = document.getElementById(id);
    if (!el) throw new Error(`qr.js: element not found: ${id}`);
    return el;
  }

  function clear(el) {
    while (el.firstChild) el.removeChild(el.firstChild);
  }

  function makeRemoteImg(data, size) {
    const url = `https://api.qrserver.com/v1/create-qr-code/?ecc=L&margin=8&size=${size}x${size}&data=${encodeURIComponent(data)}`;
    const img = document.createElement("img");
    img.alt = "QR";
    img.src = url;
    img.style.width = size + "px";
    img.style.height = size + "px";
    img.style.imageRendering = "pixelated";
    return img;
  }

  window.makeQR = function makeQR(elId, data, size = 320) {
    const el = elById(elId);
    clear(el);

    if (typeof window.QRCode !== "undefined" && typeof window.QRCode.toCanvas === "function") {
      const canvas = document.createElement("canvas");
      canvas.width = size;
      canvas.height = size;
      canvas.style.width = size + "px";
      canvas.style.height = size + "px";
      canvas.style.imageRendering = "pixelated";

      // Lowest density + bigger quiet zone
      const opts = {
        errorCorrectionLevel: "L",
        margin: 8,
        width: size,
        color: { dark: "#000000", light: "#ffffff" }
      };

      window.QRCode.toCanvas(canvas, data, opts, (err) => {
        if (err) {
          el.appendChild(makeRemoteImg(data, size));
          return;
        }
        el.appendChild(canvas);
      });

      return;
    }

    el.appendChild(makeRemoteImg(data, size));
  };

  window.scanQR = function scanQR(targetElId) {
    return new Promise((resolve, reject) => {
      if (typeof Html5Qrcode === "undefined") {
        reject(new Error("Html5Qrcode not loaded."));
        return;
      }

      const qr = new Html5Qrcode(targetElId);

      qr.start(
        { facingMode: "environment" },
        {
          fps: 12,
          qrbox: { width: 320, height: 320 },
          disableFlip: false,
          videoConstraints: {
            width: { ideal: 1920 },
            height: { ideal: 1080 },
            frameRate: { ideal: 30 }
          }
        },
        async (text) => {
          try { await qr.stop(); } catch {}
          try { await qr.clear(); } catch {}
          resolve(text);
        },
        () => {}
      ).catch(err => reject(err));
    });
  };
})();
