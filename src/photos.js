const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const jpeg = require("jpeg-js");

function privateDir() {
  if (process.env.DATA_PATH) return path.join(path.dirname(process.env.DATA_PATH), "private");
  return path.join(__dirname, "..", "data", "private");
}

function decodeBase64(value) {
  const raw = String(value || "").replace(/^data:image\/\w+;base64,/, "").replace(/\s/g, "");
  if (!raw) return null;
  return Buffer.from(raw, "base64");
}

function reencode(buffer) {
  const decoded = jpeg.decode(buffer, { useTArray: true, formatAsRGBA: true, maxMemoryUsageInMB: 32 });
  if (!decoded || !decoded.width || !decoded.height) {
    const error = new Error("photo");
    throw error;
  }
  const encoded = jpeg.encode({ data: decoded.data, width: decoded.width, height: decoded.height }, 75);
  return Buffer.from(encoded.data);
}

function storePrivatePhoto(base64) {
  const original = decodeBase64(base64);
  if (!original || !original.length || original.length > 4000000) {
    return { error: "Take a door photo with the camera." };
  }
  let clean;
  try {
    clean = reencode(original);
  } catch {
    return { error: "Take a door photo with the camera." };
  }
  const id = crypto.randomUUID();
  const dir = privateDir();
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${id}.jpg`), clean);
  return {
    id,
    sha256: crypto.createHash("sha256").update(clean).digest("hex"),
    bytes: clean.length,
  };
}

module.exports = { storePrivatePhoto, reencode, privateDir };
