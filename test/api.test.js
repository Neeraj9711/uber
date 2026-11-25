const assert = require("assert");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

process.env.DATA_PATH = path.join(os.tmpdir(), `pop-drivers-${Date.now()}.json`);
process.env.JWT_SECRET = "test-secret";
process.env.DEMO_MODE = "true";

const { createApp } = require("../src/index");

async function main() {
  const server = createApp().listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;

  async function call(urlPath, { method = "GET", token, body, headers } = {}) {
    const response = await fetch(base + urlPath, {
      method,
      headers: {
        "content-type": "application/json",
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...headers,
      },
      body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
    });
    const text = await response.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
    return { status: response.status, data };
  }

  async function restaurant(email, pin) {
    const login = await call("/auth/restaurant/login", {
      method: "POST",
      body: { email, password: "PopDrivers123!" },
    });
    assert.strictEqual(login.status, 200);
    const unlocked = await call("/auth/restaurant/pin", {
      method: "POST",
      body: { loginTicket: login.data.loginTicket, pin },
    });
    assert.strictEqual(unlocked.status, 200);
    return unlocked.data.token;
  }

  const owner = await restaurant("owner@papas.example", "1111");
  const counter = await restaurant("counter@papas.example", "3333");
  const noodle = await restaurant("owner@noodle.example", "4444");

  const billing = await call("/restaurant/billing", { token: counter });
  assert.strictEqual(billing.status, 403);

  const hidden = await call("/restaurant/orders/ord_open", { token: noodle });
  assert.strictEqual(hidden.status, 404);

  const created = await call("/restaurant/orders", {
    method: "POST",
    token: owner,
    body: {
      customerName: "Alex Kim",
      phone: "4155550199",
      address: "18 Oak Street, San Francisco",
      bags: 2,
      tip: 4,
      restaurantFee: 999,
      driverTotal: 999,
    },
  });
  assert.strictEqual(created.status, 201);
  assert.strictEqual(created.data.order.pay.restaurantFee, 7.25);
  assert.strictEqual(created.data.order.pay.driverTotal, 9.26);
  assert.strictEqual(created.data.order.status, "created");

  const cancel = await call(`/restaurant/orders/${created.data.order.id}/cancel`, {
    method: "POST",
    token: counter,
  });
  assert.strictEqual(cancel.status, 403);

  const raw = JSON.stringify({
    restaurantId: "rest_papas",
    externalId: "pos-1",
    sentAt: new Date().toISOString(),
    nonce: crypto.randomUUID(),
    customerName: "Pos Guest",
    phone: "4155550188",
    address: "12 Market Street, San Francisco",
    tip: 3,
    bags: 1,
  });
  const bad = await call("/pos/webhook", {
    method: "POST",
    body: raw,
    headers: { "x-pop-signature": "nope" },
  });
  assert.strictEqual(bad.status, 401);
  const signature = crypto.createHmac("sha256", "papas-demo-secret").update(raw).digest("hex");
  const imported = await call("/pos/webhook", {
    method: "POST",
    body: raw,
    headers: { "x-pop-signature": signature },
  });
  assert.strictEqual(imported.status, 201);
  assert.strictEqual(imported.data.order.source, "pos");
  const replay = await call("/pos/webhook", {
    method: "POST",
    body: raw,
    headers: { "x-pop-signature": signature },
  });
  assert.strictEqual(replay.status, 409);

  const otp = await call("/auth/driver/otp/request", {
    method: "POST",
    body: { phone: "+15551230001" },
  });
  assert.strictEqual(otp.status, 200);
  const signed = await call("/auth/driver/otp/verify", {
    method: "POST",
    body: { phone: "+15551230001", code: otp.data.devCode, deviceId: "phone-a" },
  });
  assert.strictEqual(signed.status, 200);
  const driver = signed.data.token;

  const online = await call("/driver/online", {
    method: "POST",
    token: driver,
    body: { online: true, location: { lat: 37.7749, lng: -122.4194 } },
  });
  assert.strictEqual(online.status, 200);
  assert.ok(online.data.offer);
  assert.strictEqual(online.data.offer.order.area, "San Francisco");
  assert.strictEqual(online.data.offer.order.address, undefined);
  assert.strictEqual(online.data.offer.order.pay.driverTotal, 9.26);

  const declined = await call(`/driver/offers/${online.data.offer.offerId}/decline`, {
    method: "POST",
    token: driver,
  });
  assert.strictEqual(declined.status, 200);
  assert.strictEqual(declined.data.lifetimeCompleted, 112);
  assert.strictEqual(declined.data.level, "silver");

  const accepted = await call("/driver/open/ord_open/accept", { method: "POST", token: driver });
  assert.strictEqual(accepted.status, 200);
  assert.strictEqual(accepted.data.delivery.stop.label, "Papa's Pizza");

  const far = await call("/driver/delivery/arrived", {
    method: "POST",
    token: driver,
    body: { lat: 0, lng: 0 },
  });
  assert.strictEqual(far.status, 400);

  const arrived = await call("/driver/delivery/arrived", {
    method: "POST",
    token: driver,
    body: { lat: 37.7749, lng: -122.4194 },
  });
  assert.strictEqual(arrived.status, 200);

  const picked = await call("/driver/delivery/pickup", {
    method: "POST",
    token: driver,
    body: { orderChecked: true, bagsChecked: true, drinksChecked: true },
  });
  assert.strictEqual(picked.status, 200);
  assert.ok(picked.data.delivery.stop.label.includes("Oak Street"));

  const proofFar = await call("/driver/delivery/proof", {
    method: "POST",
    token: driver,
    body: { type: "photo", lat: 0, lng: 0 },
  });
  assert.strictEqual(proofFar.status, 400);

  const jpeg = require("jpeg-js");
  const door = jpeg.encode({ data: Buffer.alloc(16, 200), width: 2, height: 2 }, 60);
  const proof = await call("/driver/delivery/proof", {
    method: "POST",
    token: driver,
    body: { type: "photo", photoBase64: Buffer.from(door.data).toString("base64"), ...picked.data.delivery.stop.point },
  });
  assert.strictEqual(proof.status, 200);
  assert.ok(!JSON.stringify(proof.data).includes("privateId"));
  assert.strictEqual(proof.data.level.lifetimeCompleted, 113);
  assert.strictEqual(proof.data.delivery.area, "Hidden");

  const track = await call("/track/trk_open_oak_street_demo", {
    headers: { accept: "application/json" },
  });
  assert.strictEqual(track.status, 404);

  const badPassword = await call("/auth/driver/login", {
    method: "POST",
    body: { email: "raj@example.com", password: "wrong-password" },
  });
  assert.strictEqual(badPassword.status, 401);

  const emailLogin = await call("/auth/driver/login", {
    method: "POST",
    body: { email: "raj@example.com", password: "PopDrivers123!", deviceId: "phone-email" },
  });
  assert.strictEqual(emailLogin.status, 200);
  assert.strictEqual(emailLogin.data.driver.email, "raj@example.com");
  assert.strictEqual(emailLogin.data.driver.level, "silver");

  const shortPassword = await call("/auth/driver/signup", {
    method: "POST",
    body: { name: "Ada", email: "ada@example.com", password: "short" },
  });
  assert.strictEqual(shortPassword.status, 400);

  const signedUp = await call("/auth/driver/signup", {
    method: "POST",
    body: { name: "Ada Lovelace", email: "ada@example.com", password: "PopDrivers123!", deviceId: "phone-ada" },
  });
  assert.strictEqual(signedUp.status, 201);
  assert.strictEqual(signedUp.data.driver.status, "approved");
  assert.strictEqual(signedUp.data.driver.name, "Ada Lovelace");

  const duplicate = await call("/auth/driver/signup", {
    method: "POST",
    body: { name: "Ada", email: "ada@example.com", password: "PopDrivers123!" },
  });
  assert.strictEqual(duplicate.status, 409);

  const shortRestaurant = await call("/auth/restaurant/signup", {
    method: "POST",
    body: { name: "Ada", restaurantName: "Ada Cafe", email: "ada-cafe@example.com", password: "short" },
  });
  assert.strictEqual(shortRestaurant.status, 400);

  const cafe = await call("/auth/restaurant/signup", {
    method: "POST",
    body: { name: "Ada Lovelace", restaurantName: "Ada Cafe", email: "ada-cafe@example.com", password: "PopDrivers123!" },
  });
  assert.strictEqual(cafe.status, 201);
  assert.strictEqual(cafe.data.staff.role, "owner");
  assert.strictEqual(cafe.data.staff.restaurantName, "Ada Cafe");

  const duplicateCafe = await call("/auth/restaurant/signup", {
    method: "POST",
    body: { name: "Ada", restaurantName: "Ada Cafe", email: "ada-cafe@example.com", password: "PopDrivers123!" },
  });
  assert.strictEqual(duplicateCafe.status, 409);

  const badCafe = await call("/auth/restaurant/email-login", {
    method: "POST",
    body: { email: "ada-cafe@example.com", password: "PopDrivers999!" },
  });
  assert.strictEqual(badCafe.status, 401);

  const cafeLogin = await call("/auth/restaurant/email-login", {
    method: "POST",
    body: { email: "owner@papas.example", password: "PopDrivers123!" },
  });
  assert.strictEqual(cafeLogin.status, 200);
  assert.strictEqual(cafeLogin.data.staff.restaurantName, "Papa's Pizza");
  assert.strictEqual(cafeLogin.data.staff.role, "owner");

  const forced = await call("/app/release?version=0.9.0&deviceId=phone");
  assert.strictEqual(forced.status, 200);
  assert.strictEqual(forced.data.updateRequired, true);
  const currentRelease = await call("/app/release?version=1.0.0&deviceId=phone");
  assert.strictEqual(currentRelease.data.updateRequired, false);

  const token = emailLogin.data.token;
  const mocked = await call("/driver/online", {
    method: "POST",
    token,
    body: { online: true, mocked: true, location: { lat: 37.7749, lng: -122.4194 } },
  });
  assert.strictEqual(mocked.status, 403);

  const earnings = await call("/driver/earnings", { token });
  assert.strictEqual(earnings.status, 200);
  assert.strictEqual(typeof earnings.data.today, "number");
  assert.ok(Array.isArray(earnings.data.pastWeeks));
  assert.strictEqual(typeof earnings.data.miles, "number");

  const level = await call("/driver/level", { token });
  assert.strictEqual(level.status, 200);
  assert.ok(Array.isArray(level.data.history));
  assert.ok(level.data.rolling);

  const thumbOrder = await call("/restaurant/orders", {
    method: "POST",
    token: cafeLogin.data.token,
    body: { customerName: "Thumb", phone: "4155550100", address: "18 Oak Street, San Francisco", bags: 1, tip: 0 },
  });
  assert.strictEqual(thumbOrder.status, 201);
  const requested = await call(`/restaurant/orders/${thumbOrder.data.order.id}/request-driver`, {
    method: "POST",
    token: cafeLogin.data.token,
  });
  assert.strictEqual(requested.status, 200);
  await new Promise((resolve) => setTimeout(resolve, 11000));
  const onlineAgain = await call("/driver/online", {
    method: "POST",
    token,
    body: { online: true, location: { lat: 37.7749, lng: -122.4194 } },
  });
  assert.strictEqual(onlineAgain.status, 200);
  assert.ok(onlineAgain.data.offer);
  const taken = await call(`/driver/offers/${onlineAgain.data.offer.offerId}/accept`, { method: "POST", token });
  assert.strictEqual(taken.status, 200);
  const share = await call("/driver/safety/report", { method: "POST", token, body: { type: "share", note: "" } });
  assert.strictEqual(share.status, 200);
  assert.ok(share.data.sharePath);
  const thumb = await call(`${share.data.sharePath}/thumb?vote=up`);
  assert.strictEqual(thumb.status, 200);

  const skippedReview = await call("/jobs/monthly-review", { method: "POST", body: { now: "2026-11-25T12:00:00" } });
  assert.strictEqual(skippedReview.status, 200);
  assert.strictEqual(skippedReview.data.ran, false);
  const monthReview = await call("/jobs/monthly-review", { method: "POST", body: { now: "2026-12-01T12:00:00" } });
  assert.strictEqual(monthReview.status, 200);
  assert.strictEqual(monthReview.data.ran, true);
  const levelView = await call("/driver/level", { token });
  assert.ok(Array.isArray(levelView.data.ratings));
  assert.ok(Array.isArray(levelView.data.latePickups));

  const spanish = await call("/auth/driver/login", {
    method: "POST",
    headers: { "accept-language": "es" },
    body: { email: "missing@example.com", password: "nope" },
  });
  assert.strictEqual(spanish.status, 401);
  assert.strictEqual(spanish.data.error, "No se pudo entrar.");
  const chinese = await call("/driver/level", { token, headers: { "accept-language": "zh" } });
  assert.ok(chinese.data.rewards.some((item) => String(item).includes("周四")));

  const chatSignup = await call("/auth/driver/signup", {
    method: "POST",
    body: { name: "Chat Driver", email: "chat-driver@example.com", password: "PopDrivers123!", deviceId: "chat-phone" },
  });
  assert.strictEqual(chatSignup.status, 201);
  const chatToken = chatSignup.data.token;
  const posted = await call("/driver/dispatch/chat", {
    method: "POST",
    token: chatToken,
    body: { text: "Where is the restaurant door?" },
  });
  assert.strictEqual(posted.status, 200);
  assert.strictEqual(posted.data.messages[0].from, "driver");
  assert.strictEqual(posted.data.messages[0].text, "Where is the restaurant door?");
  const emergency = await call("/driver/safety/report", {
    method: "POST",
    token: chatToken,
    body: { type: "emergency", note: "Emergency call", lat: 37.77, lng: -122.42 },
  });
  assert.strictEqual(emergency.status, 200);
  assert.strictEqual(emergency.data.dial, "tel:911");
  assert.ok(emergency.data.reportedAt);
  assert.strictEqual(emergency.data.location.lat, 37.77);
  const removed = await call("/driver/account/delete", { method: "POST", token: chatToken, body: { confirm: "DELETE" } });
  assert.strictEqual(removed.status, 200);
  assert.strictEqual(removed.data.deleted, true);
  const signedOut = await call("/driver/dispatch/chat", { token: chatToken });
  assert.strictEqual(signedOut.status, 401);

  const fs = require("fs");
  const photoPath = require("path");
  const { storePrivatePhoto, reencode, privateDir } = require("../src/photos");
  const photoRaw = jpeg.encode({ data: Buffer.alloc(16, 255), width: 2, height: 2 }, 50);
  const exif = Buffer.from([0xff, 0xe1, 0x00, 0x08, 0x45, 0x78, 0x69, 0x66, 0x00, 0x00]);
  const marked = Buffer.concat([Buffer.from(photoRaw.data).subarray(0, 2), exif, Buffer.from(photoRaw.data).subarray(2)]);
  assert.ok(marked.includes(Buffer.from("Exif")));
  const clean = reencode(marked);
  assert.ok(!clean.includes(Buffer.from("Exif")));
  const stored = storePrivatePhoto(marked.toString("base64"));
  assert.ok(stored.sha256);
  const saved = fs.readFileSync(photoPath.join(privateDir(), `${stored.id}.jpg`));
  assert.ok(!saved.includes(Buffer.from("Exif")));
  assert.ok(!JSON.stringify(stored).includes("photoBase64"));

  server.close();
  console.log("api ok");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
