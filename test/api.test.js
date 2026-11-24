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

  const proof = await call("/driver/delivery/proof", {
    method: "POST",
    token: driver,
    body: { type: "photo", ...picked.data.delivery.stop.point },
  });
  assert.strictEqual(proof.status, 200);
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

  server.close();
  console.log("api ok");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
