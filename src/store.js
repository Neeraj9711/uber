const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const { levelFor, quoteDelivery } = require("./rules");

const DEFAULT_PATH = path.join(__dirname, "..", "data", "db.json");

function dataPath() {
  return process.env.DATA_PATH || DEFAULT_PATH;
}

function load() {
  return JSON.parse(fs.readFileSync(dataPath(), "utf8"));
}

function save(db) {
  const file = dataPath();
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(db, null, 2));
}

function update(mutator) {
  const db = load();
  const result = mutator(db);
  save(db);
  return result === undefined ? db : result;
}

function hash(value) {
  return bcrypt.hashSync(value, 8);
}

function daysFromNow(days) {
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
}

function hoursFromNow(hours) {
  return new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();
}

function seed() {
  const papas = { lat: 37.7749, lng: -122.4194 };
  const noodlePoint = { lat: 37.7849, lng: -122.4094 };
  const donePay = quoteDelivery({ distanceMiles: 1.8, tip: 5 });
  const openPay = quoteDelivery({ distanceMiles: 2.2, tip: 4 });
  const password = hash("PopDrivers123!");

  const db = {
    restaurants: [
      {
        id: "rest_papas",
        name: "Papa's Pizza",
        zone: "mission",
        location: papas,
        address: "100 Market Street, San Francisco",
        phone: "4155550100",
        posSecret: "papas-demo-secret",
        posConnected: false,
        posProvider: null,
      },
      {
        id: "rest_noodle",
        name: "Noodle House",
        zone: "chinatown",
        location: noodlePoint,
        address: "88 Jackson Street, San Francisco",
        phone: "4155550108",
        posSecret: "noodle-demo-secret",
        posConnected: false,
        posProvider: null,
      },
    ],
    staff: [
      staff("staff_owner", "rest_papas", "Maria Alvarez", "owner@papas.example", "owner", "1111", password),
      staff("staff_manager", "rest_papas", "Luis Ortega", "manager@papas.example", "manager", "2222", password),
      staff("staff_counter", "rest_papas", "Ava Cole", "counter@papas.example", "counter", "3333", password),
      staff("staff_noodle", "rest_noodle", "Mei Chen", "owner@noodle.example", "owner", "4444", password),
    ],
    admins: [
      {
        id: "admin_1",
        name: "Dispatch Lead",
        email: "admin@popdrivers.example",
        passwordHash: password,
        role: "admin",
        sessionVersion: 1,
      },
    ],
    drivers: [
      {
        id: "drv_raj",
        name: "Neeraj",
        firstName: "Neeraj",
        phone: "+15551230001",
        email: "raj@example.com",
        passwordHash: password,
        status: "approved",
        sessionVersion: 1,
        deviceId: null,
        online: false,
        vehicle: "car",
        lifetimeCompleted: 112,
        level: levelFor(112),
        levelReachedAt: daysFromNow(-20),
        qualityStatus: "ok",
        atRiskSince: null,
        paused: false,
        ratingAvg: 4.92,
        ratingCount: 24,
        onTimePct: 96,
        cancelPct: 1,
        cashoutsThisWeek: 0,
        bankLast4: "4242",
        pendingPayout: null,
        photoRecheck: false,
        preferences: {
          maxDistance: 8,
          alcoholOk: true,
          largeOk: true,
          zones: [],
          favorites: [],
        },
        documents: [
          { type: "license", expiresAt: daysFromNow(40), status: "valid" },
          { type: "registration", expiresAt: daysFromNow(80), status: "valid" },
          { type: "insurance", expiresAt: daysFromNow(20), status: "valid" },
        ],
        trainingComplete: true,
        location: papas,
      },
      {
        id: "drv_new",
        name: "Sam Lee",
        firstName: "Sam",
        phone: "+15551230002",
        email: "",
        status: "action_needed",
        sessionVersion: 1,
        deviceId: null,
        online: false,
        vehicle: "bicycle",
        lifetimeCompleted: 0,
        level: "starter",
        levelReachedAt: null,
        qualityStatus: "ok",
        atRiskSince: null,
        paused: false,
        ratingAvg: 0,
        ratingCount: 0,
        onTimePct: 100,
        cancelPct: 0,
        cashoutsThisWeek: 0,
        bankLast4: null,
        pendingPayout: null,
        photoRecheck: false,
        preferences: { maxDistance: 5, alcoholOk: false, largeOk: false, zones: [] },
        documents: [],
        trainingComplete: false,
        location: papas,
      },
    ],
    orders: [
      {
        id: "ord_done",
        restaurantId: "rest_papas",
        customerName: "Jordan Blake",
        phone: "4155550177",
        address: "12 Mission Street, San Francisco",
        area: "San Francisco",
        notes: "Leave at the desk",
        bags: 1,
        alcohol: false,
        large: false,
        tip: 5,
        readyAt: daysFromNow(-1),
        distanceMiles: 1.8,
        zone: "mission",
        status: "delivered",
        driverId: "drv_raj",
        pay: donePay,
        proof: { type: "photo", metadataStripped: true },
        pin: null,
        trackingToken: "trk_done_demo_token_not_live",
        createdAt: daysFromNow(-1),
        requestedAt: daysFromNow(-1),
        deliveredAt: daysFromNow(-1),
        restaurantLocation: papas,
        dropoff: { lat: papas.lat - 0.02, lng: papas.lng - 0.01 },
        declines: [],
        rating: 5,
        locationChecks: { pickup: true, dropoff: true },
        countedForLevel: true,
      },
      {
        id: "ord_open",
        restaurantId: "rest_papas",
        customerName: "Sam Rivera",
        phone: "4155550166",
        address: "18 Oak Street, San Francisco",
        area: "San Francisco",
        notes: "Gate code 4412",
        bags: 2,
        alcohol: false,
        large: false,
        tip: 4,
        readyAt: new Date(Date.now() + 20 * 60 * 1000).toISOString(),
        distanceMiles: 2.2,
        zone: "mission",
        status: "requested",
        driverId: null,
        pay: openPay,
        proof: null,
        pin: null,
        trackingToken: "trk_open_oak_street_demo",
        createdAt: new Date(Date.now() - 2 * 60 * 1000).toISOString(),
        requestedAt: new Date(Date.now() - 60 * 1000).toISOString(),
        restaurantLocation: papas,
        dropoff: { lat: papas.lat - 0.02, lng: papas.lng - 0.02 },
        declines: [],
        rating: null,
        locationChecks: { pickup: false, dropoff: false },
        countedForLevel: false,
      },
    ],
    offers: [],
    shifts: [
      {
        id: "shift_soon",
        restaurantId: "rest_papas",
        start: hoursFromNow(30),
        end: hoursFromNow(34),
        hourlyGuarantee: 22,
        bookedBy: null,
      },
      {
        id: "shift_later",
        restaurantId: "rest_papas",
        start: hoursFromNow(36),
        end: hoursFromNow(40),
        hourlyGuarantee: 22,
        bookedBy: null,
      },
    ],
    inbox: [
      {
        id: "msg_1",
        driverId: "drv_raj",
        title: "Insurance reminder",
        body: "Your insurance expires in 20 days. Renew it in Documents so you are not taken offline.",
        at: new Date().toISOString(),
      },
      {
        id: "msg_2",
        driverId: "drv_raj",
        title: "You are Silver",
        body: "112 finished deliveries. 38 more to Gold. Declining a request does not change your level.",
        at: new Date().toISOString(),
      },
    ],
    levelEvents: [
      {
        id: "lvl_1",
        driverId: "drv_raj",
        from: "bronze",
        to: "silver",
        reason: "milestone",
        actorId: "server",
        note: "Reached 100 verified deliveries",
        at: daysFromNow(-20),
      },
    ],
    audit: [],
    otps: [],
    pinTickets: [],
    nonces: [],
    disputes: [],
  };

  save(db);
  return db;
}

function staff(id, restaurantId, name, email, role, pin, passwordHash) {
  return {
    id,
    restaurantId,
    name,
    email,
    role,
    pinHash: hash(pin),
    passwordHash,
    sessionVersion: 1,
    active: true,
  };
}

function ensure() {
  if (!fs.existsSync(dataPath())) return seed();
  const db = load();
  let changed = false;
  for (const driver of db.drivers || []) {
    if (String(driver.email || "").toLowerCase() === "raj@example.com" && !driver.passwordHash) {
      driver.passwordHash = hash("PopDrivers123!");
      changed = true;
    }
    if (String(driver.email || "").toLowerCase() === "raj@example.com" && (driver.name === "Raj Patel" || driver.firstName === "Raj")) {
      driver.name = "Neeraj";
      driver.firstName = "Neeraj";
      changed = true;
    }
    driver.preferences = driver.preferences || {};
    if (!Array.isArray(driver.preferences.favorites)) {
      driver.preferences.favorites = [];
      changed = true;
    }
  }
  if (!Array.isArray(db.qualitySnapshots)) {
    db.qualitySnapshots = [];
    changed = true;
  }
  if (!Array.isArray(db.dispatchMessages)) {
    db.dispatchMessages = [];
    changed = true;
  }
  if (!Array.isArray(db.safetyReports)) {
    db.safetyReports = [];
    changed = true;
  }
  if (!Array.isArray(db.paymentIssues)) {
    db.paymentIssues = [];
    changed = true;
  }
  if (changed) save(db);
  return db;
}

module.exports = { load, save, update, ensure, seed, dataPath };
