const crypto = require("crypto");
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { ensure, update } = require("./store");
const rules = require("./rules");
const { localize } = require("./messages");
const { storePrivatePhoto } = require("./photos");

const DEMO = process.env.DEMO_MODE !== "false";
const SECRET = process.env.JWT_SECRET || "pop-drivers-dev-secret";
const MASKED_DIAL = "4155550136";
const RESTAURANT_DIAL = "4155550148";
const SUPPORT_DIAL = "4155550199";

function createApp() {
  ensure();
  const app = express();
  app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Pop-Signature, Accept-Language");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
    if (req.method === "OPTIONS") return res.sendStatus(204);
    const send = res.json.bind(res);
    res.json = (body) => send(localize(req, body));
    next();
  });
  app.use(
    express.json({
      limit: "6mb",
      verify: (req, _res, buf) => {
        req.rawBody = buf;
      },
    })
  );
  app.use((err, _req, res, next) => {
    if (err && err.type === "entity.parse.failed") {
      return res.status(400).json({ error: "That request could not be read." });
    }
    return next(err);
  });

  app.get("/health", (_req, res) => res.json({ ok: true }));

  app.get("/app/release", (req, res) => {
    const client = String(req.query.version || "0.0.0");
    const deviceId = String(req.query.deviceId || "device");
    const release = {
      version: process.env.APP_VERSION || "1.0.0",
      minVersion: process.env.APP_MIN_VERSION || "1.0.0",
      rolloutPercent: Number(process.env.APP_ROLLOUT_PERCENT || 100),
    };
    const inCohort = rules.inRollout(deviceId, release.rolloutPercent);
    res.json({
      ...release,
      inCohort,
      updateRequired: rules.versionBelow(client, release.minVersion) && inCohort,
    });
  });

  app.post("/auth/driver/otp/request", (req, res) => {
    const phone = normalizePhone(req.body.phone);
    if (!phone) return res.status(400).json({ error: "Enter a phone number." });
    const result = update((db) => {
      const recent = db.otps.filter(
        (item) => item.phone === phone && Date.now() - new Date(item.sentAt).getTime() < 15 * 60 * 1000
      );
      if (recent.length >= 5) return { error: "Please wait and try again.", status: 429 };
      let driver = db.drivers.find((item) => item.phone === phone);
      if (!driver) {
        driver = newDriver(phone);
        db.drivers.push(driver);
      }
      const code = String(crypto.randomInt(100000, 999999));
      db.otps.push({
        phone,
        codeHash: bcrypt.hashSync(code, 6),
        sentAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
        attempts: 0,
      });
      audit(db, { actorId: driver.id, action: "driver_otp_sent", phoneLast4: phone.slice(-4) });
      return { devCode: DEMO ? code : undefined };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json({ ok: true, message: "If the number can be used, a code was sent.", ...result });
  });

  app.post("/auth/driver/otp/verify", (req, res) => {
    const phone = normalizePhone(req.body.phone);
    const code = String(req.body.code || "");
    const deviceId = String(req.body.deviceId || "device");
    const result = update((db) => {
      const otp = [...db.otps].reverse().find((item) => item.phone === phone);
      const driver = db.drivers.find((item) => item.phone === phone);
      const generic = { error: "Could not sign in.", status: 401 };
      if (driver && driver.status === "deleted") return { error: "This account was deleted.", status: 401 };
      if (!otp || !driver) return generic;
      if (new Date(otp.expiresAt).getTime() < Date.now() || otp.attempts >= 5) return generic;
      otp.attempts += 1;
      if (!bcrypt.compareSync(code, otp.codeHash)) return generic;
      const previous = driver.deviceId;
      driver.deviceId = deviceId;
      driver.sessionVersion += 1;
      if (previous && previous !== deviceId) {
        audit(db, { actorId: driver.id, action: "driver_new_device" });
      }
      audit(db, { actorId: driver.id, action: "driver_sign_in" });
      return { token: signToken(driverToken(driver)), driver: publicDriver(driver) };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.post("/auth/driver/signup", (req, res) => {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");
    const name = String(req.body.name || "").trim();
    if (!email) return res.status(400).json({ error: "Enter an email address." });
    if (password.length < 8) return res.status(400).json({ error: "Use a password of at least 8 characters." });
    if (!name) return res.status(400).json({ error: "Enter your name." });
    const result = update((db) => {
      if (db.drivers.some((item) => item.email && item.email.toLowerCase() === email)) {
        return { error: "That email is already in use.", status: 409 };
      }
      const driver = newDriver(placeholderPhone(db));
      driver.name = name;
      driver.firstName = name.split(/\s+/)[0] || name;
      driver.email = email;
      driver.passwordHash = bcrypt.hashSync(password, 8);
      driver.status = "approved";
      driver.trainingComplete = true;
      driver.vehicle = "bicycle";
      driver.deviceId = String(req.body.deviceId || "device");
      db.drivers.push(driver);
      audit(db, { actorId: driver.id, action: "driver_email_signup" });
      return { token: signToken(driverToken(driver)), driver: publicDriver(driver) };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.status(201).json(result);
  });

  app.post("/auth/driver/login", (req, res) => {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");
    const deviceId = String(req.body.deviceId || "device");
    if (!email || !password) return res.status(400).json({ error: "Enter your email and password." });
    const result = update((db) => {
      const driver = db.drivers.find((item) => item.email && item.email.toLowerCase() === email);
      if (driver && driver.status === "deleted") return { error: "This account was deleted.", status: 401 };
      if (!driver || !driver.passwordHash || !bcrypt.compareSync(password, driver.passwordHash)) {
        return { error: "Could not sign in.", status: 401 };
      }
      driver.deviceId = deviceId;
      driver.sessionVersion += 1;
      audit(db, { actorId: driver.id, action: "driver_email_sign_in" });
      return { token: signToken(driverToken(driver)), driver: publicDriver(driver) };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.post("/auth/restaurant/signup", (req, res) => {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");
    const name = String(req.body.name || "").trim();
    const restaurantName = String(req.body.restaurantName || "").trim();
    const passwordError = restaurantPasswordError(password);
    if (!email) return res.status(400).json({ error: "Enter an email address." });
    if (passwordError) return res.status(400).json({ error: passwordError });
    if (!name) return res.status(400).json({ error: "Enter your name." });
    if (restaurantName.length < 2) return res.status(400).json({ error: "Enter the restaurant name." });
    const result = update((db) => {
      if (db.staff.some((item) => item.email === email)) {
        return { error: "That email is already in use.", status: 409 };
      }
      const restaurant = {
        id: crypto.randomUUID(),
        name: restaurantName.slice(0, 80),
        zone: "mission",
        location: { lat: 37.7749, lng: -122.4194 },
        address: "San Francisco",
        phone: "",
        posSecret: crypto.randomBytes(16).toString("hex"),
        posConnected: false,
        posProvider: null,
      };
      const person = {
        id: crypto.randomUUID(),
        restaurantId: restaurant.id,
        name: name.slice(0, 80),
        email,
        role: "owner",
        pinHash: bcrypt.hashSync("1111", 8),
        passwordHash: bcrypt.hashSync(password, 8),
        sessionVersion: 1,
        active: true,
      };
      db.restaurants.push(restaurant);
      db.staff.push(person);
      audit(db, { actorId: person.id, action: "restaurant_email_signup", restaurantId: restaurant.id });
      return { token: signToken(staffToken(person)), staff: publicStaff(person, db) };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.status(201).json(result);
  });

  app.post("/auth/restaurant/email-login", (req, res) => {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");
    if (!email || !password) return res.status(400).json({ error: "Enter your email and password." });
    const passwordError = restaurantPasswordError(password);
    if (passwordError) return res.status(400).json({ error: passwordError });
    const result = update((db) => {
      const person = db.staff.find((item) => item.email === email && item.active);
      if (!person || !bcrypt.compareSync(password, person.passwordHash)) {
        return { error: "Could not sign in.", status: 401 };
      }
      person.sessionVersion += 1;
      audit(db, { actorId: person.id, action: "restaurant_email_sign_in", restaurantId: person.restaurantId });
      return { token: signToken(staffToken(person)), staff: publicStaff(person, db) };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.post("/auth/restaurant/login", (req, res) => {
    const email = String(req.body.email || "").toLowerCase().trim();
    const password = String(req.body.password || "");
    const passwordError = restaurantPasswordError(password);
    if (passwordError) return res.status(400).json({ error: passwordError });
    const result = update((db) => {
      const person = db.staff.find((item) => item.email === email && item.active);
      if (!person || !bcrypt.compareSync(password, person.passwordHash)) {
        return { error: "Could not sign in.", status: 401 };
      }
      const ticket = crypto.randomUUID();
      db.pinTickets.push({
        id: ticket,
        staffId: person.id,
        expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      });
      return {
        pinRequired: true,
        loginTicket: ticket,
        name: person.name,
        restaurantName: db.restaurants.find((item) => item.id === person.restaurantId).name,
      };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.post("/auth/restaurant/pin", (req, res) => {
    const result = update((db) => {
      const ticket = db.pinTickets.find((item) => item.id === req.body.loginTicket);
      if (!ticket || new Date(ticket.expiresAt).getTime() < Date.now()) {
        return { error: "Could not sign in.", status: 401 };
      }
      const person = db.staff.find((item) => item.id === ticket.staffId && item.active);
      if (!person || !bcrypt.compareSync(String(req.body.pin || ""), person.pinHash)) {
        return { error: "Could not sign in.", status: 401 };
      }
      db.pinTickets = db.pinTickets.filter((item) => item.id !== ticket.id);
      audit(db, { actorId: person.id, action: "restaurant_sign_in", restaurantId: person.restaurantId });
      return { token: signToken(staffToken(person)), staff: publicStaff(person, db) };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.post("/auth/admin/login", (req, res) => {
    const email = String(req.body.email || "").toLowerCase().trim();
    const password = String(req.body.password || "");
    const db = ensure();
    const admin = db.admins.find((item) => item.email === email);
    if (!admin || !bcrypt.compareSync(password, admin.passwordHash)) {
      return res.status(401).json({ error: "Could not sign in." });
    }
    res.json({ token: signToken({ sub: admin.id, role: "admin", sv: admin.sessionVersion }) });
  });

  app.get("/me", auth(), (req, res) => {
    if (req.user.role === "driver") return res.json({ role: "driver", driver: publicDriver(req.driver) });
    if (req.user.role === "admin") return res.json({ role: "admin" });
    res.json({ role: req.staff.role, staff: publicStaff(req.staff, ensure()) });
  });

  app.post("/driver/online", auth("driver"), (req, res) => {
    const online = Boolean(req.body.online);
    const result = update((db) => {
      const driver = fresh(db, req);
      if (online && driver.status !== "approved") {
        return { error: "Your account is not approved yet.", status: 403 };
      }
      if (online && expiredDoc(driver)) {
        return { error: "A required document has expired. You have been kept offline.", status: 403 };
      }
      const blocked = online ? rules.deviceProblem(req.body) : "";
      if (blocked) return { error: blocked, status: 403 };
      driver.online = online;
      if (online && req.body.location) driver.location = point(req.body.location) || driver.location;
      audit(db, { actorId: driver.id, action: online ? "driver_online" : "driver_offline" });
      const offer = online ? matchWaiting(db, driver) : null;
      return { online: driver.online, offer: offer ? offerPayload(db, offer) : null };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.get("/driver/offers", auth("driver"), (req, res) => {
    const payload = update((db) => {
      expireOffers(db);
      const driver = fresh(db, req);
      if (!driver.online) return { offers: [], openRequests: [] };
      const direct = db.offers.find(
        (item) => item.driverId === driver.id && item.status === "pending" && new Date(item.expiresAt) > new Date()
      );
      return {
        offers: direct ? [offerPayload(db, direct)] : [],
        openRequests: openRequestsFor(db, driver),
      };
    });
    res.json(payload);
  });

  app.post("/driver/offers/:id/accept", auth("driver"), (req, res) => {
    const result = update((db) => acceptOffer(db, fresh(db, req), req.params.id));
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.post("/driver/offers/:id/decline", auth("driver"), (req, res) => {
    const result = update((db) => {
      const driver = fresh(db, req);
      const offer = db.offers.find((item) => item.id === req.params.id && item.driverId === driver.id);
      if (!offer || offer.status !== "pending") return { error: "That offer is no longer available.", status: 409 };
      offer.status = "declined";
      const order = db.orders.find((item) => item.id === offer.orderId);
      order.declines.push(driver.id);
      audit(db, { actorId: driver.id, action: "offer_declined", orderId: order.id });
      return { ok: true, level: driver.level, lifetimeCompleted: driver.lifetimeCompleted };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.post("/driver/open/:orderId/accept", auth("driver"), (req, res) => {
    const result = update((db) => {
      const driver = fresh(db, req);
      const order = db.orders.find((item) => item.id === req.params.orderId);
      if (!order || order.status !== "requested" || order.driverId) {
        return { error: "That delivery is no longer open.", status: 409 };
      }
      if (!rules.canSeeOpenRequest(driver.level, order.requestedAt)) {
        return { error: "Gold drivers are still in their head start.", status: 403 };
      }
      if (!allows(driver, order)) return { error: "This delivery is outside your preferences.", status: 403 };
      const offer = {
        id: crypto.randomUUID(),
        orderId: order.id,
        driverId: driver.id,
        status: "pending",
        expiresAt: new Date(Date.now() + 30 * 1000).toISOString(),
      };
      db.offers.push(offer);
      return acceptOffer(db, driver, offer.id);
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.get("/driver/delivery/active", auth("driver"), (req, res) => {
    const db = ensure();
    const order = activeOrder(db, req.driver.id);
    res.json({ delivery: order ? driverView(db, order, true) : null });
  });

  app.post("/driver/delivery/arrived", auth("driver"), (req, res) => {
    const result = update((db) => {
      const order = mustActive(db, fresh(db, req).id);
      if (order.error) return order;
      const blocked = rules.deviceProblem(req.body);
      if (blocked) return { error: blocked, status: 403 };
      const here = point(req.body);
      const target = order.status === "picked_up" ? order.dropoff : order.restaurantLocation;
      const which = order.status === "picked_up" ? "dropoff" : "pickup";
      if (!rules.near(here, target)) {
        return { error: "You need to be at the stop before this can be confirmed.", status: 400 };
      }
      order.locationChecks[which] = true;
      if (which === "pickup") {
        order.status = "at_pickup";
        order.arrivedAt = new Date().toISOString();
      }
      audit(db, { actorId: order.driverId, action: "arrived", orderId: order.id, stop: which });
      return { delivery: driverView(db, order, true) };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.post("/driver/delivery/not-ready", auth("driver"), (req, res) => {
    const result = update((db) => {
      const order = mustActive(db, fresh(db, req).id);
      if (order.error) return order;
      if (order.status !== "at_pickup") return { error: "Arrive at the restaurant first.", status: 400 };
      if (order.kitchenLate) {
        return { delivery: driverView(db, order, true), note: "Wait pay is already on this order." };
      }
      const minutes = DEMO ? 16 : 0;
      const billable = Math.max(0, minutes - 10);
      order.pay.wait = rules.round(billable * 0.2);
      order.pay.driverTotal = rules.round(order.pay.driverBase + order.pay.driverMiles + order.pay.boost + order.pay.tip + order.pay.wait);
      order.pay.restaurantFee = rules.round(order.pay.restaurantFee + order.pay.wait);
      order.kitchenLate = true;
      audit(db, { actorId: order.driverId, action: "kitchen_late", orderId: order.id });
      return { delivery: driverView(db, order, true), note: "Late food is not counted against your on-time record." };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.post("/driver/delivery/pickup", auth("driver"), (req, res) => {
    const result = update((db) => {
      const order = mustActive(db, fresh(db, req).id);
      if (order.error) return order;
      if (!order.locationChecks.pickup) return { error: "Confirm that you are at the restaurant first.", status: 400 };
      if (!req.body.orderChecked || !req.body.bagsChecked || !req.body.drinksChecked) {
        return { error: "Complete the pickup checklist.", status: 400 };
      }
      order.status = "picked_up";
      order.pickedUpAt = new Date().toISOString();
      audit(db, { actorId: order.driverId, action: "picked_up", orderId: order.id });
      return { delivery: driverView(db, order, true) };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.post("/driver/delivery/call", auth("driver"), (req, res) => {
    const db = ensure();
    const order = activeOrder(db, req.driver.id);
    if (!order) return res.status(404).json({ error: "No active delivery." });
    update((current) => audit(current, { actorId: req.driver.id, action: "masked_call", orderId: order.id }));
    res.json({ display: "(415) 555-0136", dial: `tel:${MASKED_DIAL}` });
  });

  app.post("/driver/delivery/call-restaurant", auth("driver"), (req, res) => {
    const db = ensure();
    const order = activeOrder(db, req.driver.id);
    if (!order) return res.status(404).json({ error: "No active delivery." });
    if (order.status !== "accepted" && order.status !== "at_pickup") {
      return res.status(400).json({ error: "Call the restaurant during pickup." });
    }
    update((current) => audit(current, { actorId: req.driver.id, action: "masked_restaurant_call", orderId: order.id }));
    res.json({ display: "(415) 555-0148", dial: `tel:${RESTAURANT_DIAL}` });
  });

  app.post("/driver/support/call", auth("driver"), (req, res) => {
    update((current) => audit(current, { actorId: req.driver.id, action: "support_call" }));
    res.json({ display: "(415) 555-0199", dial: `tel:${SUPPORT_DIAL}` });
  });

  app.post("/driver/delivery/text", auth("driver"), (req, res) => {
    const message = String(req.body.message || "").trim();
    if (message.length < 1) return res.status(400).json({ error: "Write a message first." });
    const result = update((db) => {
      const order = mustActive(db, fresh(db, req).id);
      if (order.error) return order;
      order.texts = order.texts || [];
      order.texts.push({ at: new Date().toISOString(), body: message.slice(0, 240) });
      audit(db, { actorId: order.driverId, action: "masked_text", orderId: order.id });
      return { display: "(415) 555-0136", sent: true };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.post("/driver/delivery/mentor", auth("driver"), (req, res) => {
    const result = update((db) => {
      const driver = fresh(db, req);
      const bonus = rules.mentorBonus(driver.level);
      if (!bonus) return { error: "Mentoring pay is for Diamond drivers.", status: 403 };
      const order = mustActive(db, driver.id);
      if (order.error) return order;
      if (order.pay.mentorBonus) return { delivery: driverView(db, order, true, driver), note: "Mentoring pay is already on this order." };
      order.pay.mentorBonus = bonus;
      order.pay.driverTotal = rules.round(order.pay.driverTotal + bonus);
      audit(db, { actorId: driver.id, action: "mentor_bonus", orderId: order.id });
      return { delivery: driverView(db, order, true, driver), note: "Mentoring pay was added." };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.post("/driver/delivery/proof", auth("driver"), (req, res) => {
    const result = update((db) => {
      const driver = fresh(db, req);
      const order = mustActive(db, driver.id);
      if (order.error) return order;
      if (order.status !== "picked_up" && order.status !== "waiting_customer") {
        return { error: "Pick up the order before completing it.", status: 400 };
      }
      if (!rules.near(point(req.body), order.dropoff)) {
        return { error: "You need to be near the drop-off to finish.", status: 400 };
      }
      if (order.alcohol && String(req.body.pin || "") !== order.pin) {
        return { error: "Enter the alcohol PIN from the customer.", status: 400 };
      }
      const blocked = rules.deviceProblem(req.body);
      if (blocked) return { error: blocked, status: 403 };
      const type = req.body.type === "handoff" ? "handoff" : "photo";
      let stored = null;
      if (type === "photo") {
        stored = storePrivatePhoto(req.body.photoBase64);
        if (stored.error) return { error: stored.error, status: 400 };
      }
      order.proof = {
        type,
        metadataStripped: true,
        reencoded: type === "photo",
        storedPrivately: type === "photo",
        sha256: stored ? stored.sha256 : null,
        privateId: stored ? stored.id : null,
      };
      order.locationChecks.dropoff = true;
      order.status = "delivered";
      order.deliveredAt = new Date().toISOString();
      if (!order.countedForLevel && order.locationChecks.pickup && order.locationChecks.dropoff) {
        order.countedForLevel = true;
        driver.lifetimeCompleted += 1;
        const previous = driver.level;
        driver.level = rules.levelFor(driver.lifetimeCompleted);
        if (driver.level !== previous) {
          driver.levelReachedAt = new Date().toISOString();
          db.levelEvents.push({
            id: crypto.randomUUID(),
            driverId: driver.id,
            from: previous,
            to: driver.level,
            reason: "milestone",
            actorId: "server",
            note: "Verified delivery with proof and location checks",
            at: new Date().toISOString(),
          });
          db.inbox.push({
            id: crypto.randomUUID(),
            driverId: driver.id,
            title: `You reached ${titleCase(driver.level)}`,
            body: "Your level is calculated on the server from finished deliveries only.",
            at: new Date().toISOString(),
          });
        }
      }
      driver.online = true;
      audit(db, { actorId: driver.id, action: "delivered", orderId: order.id });
      return { delivery: driverView(db, order, true), level: publicLevel(driver) };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.post("/driver/delivery/unreachable", auth("driver"), (req, res) => {
    const result = update((db) => {
      const order = mustActive(db, fresh(db, req).id);
      if (order.error) return order;
      if (order.status !== "picked_up") return { error: "This step is available after pickup.", status: 400 };
      order.status = "waiting_customer";
      order.waitingSince = new Date().toISOString();
      audit(db, { actorId: order.driverId, action: "customer_unreachable", orderId: order.id });
      return { delivery: driverView(db, order, true), waitMinutes: 8 };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.post("/driver/delivery/return", auth("driver"), (req, res) => {
    const result = update((db) => {
      const order = mustActive(db, fresh(db, req).id);
      if (order.error) return order;
      if (order.status !== "waiting_customer") return { error: "Contact the customer before returning the order.", status: 400 };
      const waited = Date.now() - new Date(order.waitingSince).getTime();
      if (waited < 8 * 60 * 1000 && !(DEMO && req.body.demo)) {
        return { error: "Wait 8 minutes, then contact dispatch.", status: 400 };
      }
      order.status = "returned";
      order.returnPay = 4;
      order.countedForLevel = false;
      audit(db, { actorId: order.driverId, action: "returned", orderId: order.id });
      return { delivery: driverView(db, order, true), paidReturn: 4 };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.get("/driver/earnings", auth("driver"), (req, res) => {
    const db = ensure();
    const detailed = db.orders
      .filter((item) => item.driverId === req.driver.id && ["delivered", "returned"].includes(item.status))
      .map((item) => ({
        id: item.id,
        restaurantName: restaurantById(db, item.restaurantId).name,
        status: item.status,
        at: item.deliveredAt || item.createdAt,
        pay: item.pay,
        returnPay: item.returnPay || 0,
        distanceMiles: item.distanceMiles || 0,
      }));
    const split = rules.earningsSplit(detailed);
    res.json({
      payday: "Thursday",
      today: split.today,
      week: split.week,
      miles: split.miles,
      pastWeeks: split.pastWeeks,
      deliveries: detailed,
      cashOutFee: rules.cashOutFee(req.driver.level, req.driver.cashoutsThisWeek),
    });
  });

  app.get("/driver/earnings/export", auth("driver"), (req, res) => {
    const db = ensure();
    const lines = ["date,restaurant,miles,pay,status"];
    db.orders
      .filter((item) => item.driverId === req.driver.id && ["delivered", "returned"].includes(item.status))
      .forEach((item) => {
        const pay = rules.round((item.pay?.driverTotal || 0) + (item.returnPay || 0));
        const name = restaurantById(db, item.restaurantId).name.replace(/,/g, " ");
        lines.push(`${item.deliveredAt || item.createdAt},${name},${item.distanceMiles || 0},${pay},${item.status}`);
      });
    res.type("text/csv").send(lines.join("\n"));
  });

  app.get("/driver/map", auth("driver"), (req, res) => {
    const db = ensure();
    const driver = req.driver;
    const rows = db.orders
      .filter((item) => item.driverId === driver.id && ["delivered", "returned"].includes(item.status))
      .map((item) => ({
        at: item.deliveredAt || item.createdAt,
        pay: item.pay,
        returnPay: item.returnPay || 0,
        distanceMiles: item.distanceMiles || 0,
      }));
    const split = rules.earningsSplit(rows);
    const here = driver.location || { lat: 37.7749, lng: -122.4194 };
    res.json({
      earningsToday: split.today,
      zone: { name: "Your zone", lat: here.lat, lng: here.lng, radiusMiles: 2 },
      restaurants: db.restaurants.map((item) => ({ name: item.name, lat: item.location.lat, lng: item.location.lng })),
      rushAreas: [{ name: "Downtown rush", lat: here.lat + 0.01, lng: here.lng + 0.01, radiusMiles: 0.6, boost: 1 }],
    });
  });

  app.post("/driver/cashout", auth("driver"), (req, res) => {
    const result = update((db) => {
      const driver = fresh(db, req);
      const fee = rules.cashOutFee(driver.level, driver.cashoutsThisWeek);
      if (fee === 0 && driver.level === "silver") driver.cashoutsThisWeek += 1;
      else if (fee > 0) driver.cashoutsThisWeek += 1;
      audit(db, { actorId: driver.id, action: "cashout", fee });
      return { fee, message: fee === 0 ? "Instant cash-out is free at your level." : `Instant cash-out fee is $${fee.toFixed(2)}.` };
    });
    res.json(result);
  });

  app.get("/driver/level", auth("driver"), (req, res) => {
    const db = ensure();
    const quality = rules.reviewQuality(req.driver, db.orders);
    const lines = qualityLines(db, req.driver);
    res.json({ ...publicLevel(req.driver, db, quality), ratings: lines.ratings, latePickups: lines.latePickups });
  });

  app.post("/jobs/monthly-review", (req, res) => {
    const now = DEMO && req.body && req.body.now ? new Date(req.body.now) : new Date();
    const result = update((db) => applyMonthlyReview(db, now));
    res.json(result);
  });

  app.post("/driver/level/dispute", auth("driver"), (req, res) => {
    const note = String(req.body.note || "").trim();
    if (note.length < 5) return res.status(400).json({ error: "Tell us what should be reviewed." });
    const result = update((db) => {
      const driver = fresh(db, req);
      const recent = db.disputes.find(
        (item) => item.driverId === driver.id && Date.now() - new Date(item.at).getTime() < 7 * 24 * 60 * 60 * 1000
      );
      if (recent) return { error: "You can dispute one item every 7 days.", status: 400 };
      db.disputes.push({ id: crypto.randomUUID(), driverId: driver.id, note, at: new Date().toISOString() });
      audit(db, { actorId: driver.id, action: "level_dispute" });
      return { ok: true };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.get("/driver/shifts", auth("driver"), (req, res) => {
    const db = ensure();
    res.json({
      shifts: db.shifts.map((shift) => shiftView(shift, req.driver, db)),
    });
  });

  app.post("/driver/shifts/:id/book", auth("driver"), (req, res) => {
    const result = update((db) => {
      const driver = fresh(db, req);
      const shift = db.shifts.find((item) => item.id === req.params.id);
      if (!shift) return { error: "Shift not found.", status: 404 };
      if (shift.bookedBy) return { error: "That shift is already booked.", status: 409 };
      const lead = rules.shiftLeadHours(driver.level);
      if (!lead) return { error: "Restaurant shifts open at Silver.", status: 403 };
      const opens = new Date(shift.start).getTime() - lead * 60 * 60 * 1000;
      if (Date.now() < opens) return { error: "This shift is not open for your level yet.", status: 403 };
      shift.bookedBy = driver.id;
      audit(db, { actorId: driver.id, action: "shift_booked", shiftId: shift.id });
      return { shift: shiftView(shift, driver, db) };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.get("/driver/inbox", auth("driver"), (req, res) => {
    const db = ensure();
    res.json({
      messages: db.inbox
        .filter((item) => item.driverId === req.driver.id)
        .sort((a, b) => new Date(b.at) - new Date(a.at)),
    });
  });

  app.get("/driver/preferences", auth("driver"), (req, res) => {
    res.json(preferenceView(ensure(), req.driver));
  });

  app.put("/driver/preferences", auth("driver"), (req, res) => {
    const result = update((db) => {
      const driver = fresh(db, req);
      const body = req.body || {};
      const favorites = Array.isArray(body.favorites) ? body.favorites.map(String).slice(0, 3) : driver.preferences.favorites || [];
      if (["car", "motorcycle", "bicycle"].includes(body.vehicle)) driver.vehicle = body.vehicle;
      driver.preferences = {
        maxDistance: Math.min(30, Math.max(1, Number(body.maxDistance) || driver.preferences.maxDistance)),
        alcoholOk: Boolean(body.alcoholOk),
        largeOk: Boolean(body.largeOk),
        zones: Array.isArray(body.zones) ? body.zones.map(String).slice(0, 5) : driver.preferences.zones,
        favorites: rules.LEVEL_RANK[driver.level] >= rules.LEVEL_RANK.platinum ? favorites : [],
      };
      audit(db, { actorId: driver.id, action: "preferences_saved" });
      return preferenceView(db, driver);
    });
    res.json(result);
  });

  app.post("/driver/payout/change", auth("driver"), (req, res) => {
    const phone = req.driver.phone;
    const code = String(req.body.code || "");
    const last4 = String(req.body.last4 || "");
    if (!/^\d{4}$/.test(last4)) return res.status(400).json({ error: "Enter the last 4 digits only." });
    const result = update((db) => {
      const driver = fresh(db, req);
      const otp = [...db.otps].reverse().find((item) => item.phone === phone);
      if (!otp || new Date(otp.expiresAt).getTime() < Date.now() || !bcrypt.compareSync(code, otp.codeHash)) {
        return { error: "Enter a current code from your phone.", status: 401 };
      }
      const holdUntil = new Date(Date.now() + 48 * 60 * 60 * 1000).toISOString();
      driver.pendingPayout = { last4, holdUntil, previousLast4: driver.bankLast4 };
      audit(db, { actorId: driver.id, action: "payout_change_requested" });
      db.inbox.push({
        id: crypto.randomUUID(),
        driverId: driver.id,
        title: "Payout account change",
        body: "A new payout account was requested. The first payout waits 48 hours. If this was not you, call support.",
        at: new Date().toISOString(),
      });
      return { pending: driver.pendingPayout };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.get("/driver/documents", auth("driver"), (req, res) => {
    res.json({ documents: documentViews(req.driver), vehicle: req.driver.vehicle });
  });

  app.post("/driver/profile/photo", auth("driver"), (req, res) => {
    const result = update((db) => {
      const driver = fresh(db, req);
      driver.photoRecheck = true;
      audit(db, { actorId: driver.id, action: "photo_recheck" });
      return { photoRecheck: true };
    });
    res.json(result);
  });

  app.post("/driver/onboarding", auth("driver"), (req, res) => {
    const result = update((db) => {
      const driver = fresh(db, req);
      if (driver.status === "approved") return { driver: publicDriver(driver) };
      driver.name = String(req.body.name || driver.name || "").slice(0, 80) || driver.name;
      driver.firstName = driver.name.split(" ")[0] || "Driver";
      driver.vehicle = ["car", "motorcycle", "bicycle"].includes(req.body.vehicle) ? req.body.vehicle : driver.vehicle;
      driver.trainingComplete = Boolean(req.body.trainingComplete);
      if (driver.vehicle !== "bicycle") {
        const hasDocs = Boolean(req.body.documentsConfirmed);
        driver.documents = hasDocs
          ? [
              { type: "license", expiresAt: daysFromNow(200), status: "valid" },
              { type: "registration", expiresAt: daysFromNow(200), status: "valid" },
              { type: "insurance", expiresAt: daysFromNow(200), status: "valid" },
            ]
          : [];
      }
      driver.status = driver.trainingComplete ? "in_review" : "action_needed";
      audit(db, { actorId: driver.id, action: "onboarding_saved", status: driver.status });
      return { driver: publicDriver(driver) };
    });
    res.json(result);
  });

  app.get("/driver/safety", auth("driver"), (_req, res) => {
    res.json({
      actions: ["Call emergency services", "Share this trip with dispatch", "Report an unsafe address", "Report a restaurant problem"],
    });
  });

  app.post("/driver/safety/report", auth("driver"), (req, res) => {
    const note = String(req.body.note || "").trim();
    const kind = ["incident", "unsafe_address", "restaurant", "share", "emergency"].includes(req.body.type) ? req.body.type : "incident";
    if (kind !== "share" && kind !== "emergency" && note.length < 3) {
      return res.status(400).json({ error: "Tell dispatch what happened." });
    }
    const db = ensure();
    const order = activeOrder(db, req.driver.id);
    const here = point(req.body);
    const reportedAt = new Date().toISOString();
    update((current) => {
      current.safetyReports = current.safetyReports || [];
      current.safetyReports.push({
        id: crypto.randomUUID(),
        driverId: req.driver.id,
        type: kind,
        note: note.slice(0, 240),
        at: reportedAt,
        location: here,
        orderId: order ? order.id : null,
      });
      audit(current, { actorId: req.driver.id, action: `safety_${kind}`, note: note.slice(0, 240), orderId: order ? order.id : undefined });
    });
    res.json({
      ok: true,
      type: kind,
      reportedAt,
      location: here,
      dial: kind === "emergency" ? "tel:911" : null,
      message: kind === "share"
        ? "Trip share is ready."
        : kind === "emergency"
          ? "Emergency services can be called from this phone. Dispatch has the time and place."
          : "Dispatch has the time and your report.",
      sharePath: order ? `/track/${order.trackingToken}` : null,
    });
  });

  app.get("/driver/dispatch/chat", auth("driver"), (req, res) => {
    const db = ensure();
    res.json({ messages: chatFor(db, req.driver.id) });
  });

  app.post("/driver/dispatch/chat", auth("driver"), (req, res) => {
    const text = String(req.body.text || "").trim();
    if (text.length < 1) return res.status(400).json({ error: "Write a message first." });
    const result = update((db) => {
      const driver = fresh(db, req);
      db.dispatchMessages = db.dispatchMessages || [];
      db.dispatchMessages.push({
        id: crypto.randomUUID(),
        driverId: driver.id,
        from: "driver",
        text: text.slice(0, 500),
        at: new Date().toISOString(),
      });
      audit(db, { actorId: driver.id, action: "dispatch_message" });
      return { messages: chatFor(db, driver.id) };
    });
    res.json(result);
  });

  app.post("/driver/account/delete", auth("driver"), (req, res) => {
    if (String(req.body.confirm || "") !== "DELETE") {
      return res.status(400).json({ error: "Type DELETE to confirm." });
    }
    const result = update((db) => {
      const driver = fresh(db, req);
      if (activeOrder(db, driver.id)) {
        return { error: "Finish or return the active delivery before deleting the account.", status: 409 };
      }
      driver.status = "deleted";
      driver.deletedAt = new Date().toISOString();
      driver.email = `deleted+${driver.id}@pop-drivers.invalid`;
      driver.phone = "";
      driver.name = "Deleted driver";
      driver.firstName = "Deleted";
      driver.passwordHash = "";
      driver.online = false;
      driver.sessionVersion += 1;
      driver.bankLast4 = null;
      driver.pendingPayout = null;
      audit(db, { actorId: driver.id, action: "account_deleted" });
      return { deleted: true };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.get("/restaurant/orders", auth("owner", "manager", "counter"), (req, res) => {
    const db = ensure();
    const orders = db.orders
      .filter((item) => item.restaurantId === req.staff.restaurantId)
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .map((item) => restaurantOrder(db, item));
    res.json({ orders });
  });

  app.post("/restaurant/orders", auth("owner", "manager", "counter"), (req, res) => {
    const result = update((db) => createOrder(db, req.staff, req.body || {}));
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.status(201).json(result);
  });

  app.get("/restaurant/orders/:id", auth("owner", "manager", "counter"), (req, res) => {
    const db = ensure();
    const order = ownedOrder(db, req);
    if (!order) return res.status(404).json({ error: "Order not found." });
    res.json({ order: restaurantOrder(db, order) });
  });

  app.post("/restaurant/orders/:id/request-driver", auth("owner", "manager", "counter"), (req, res) => {
    const result = update((db) => {
      const staff = freshStaff(db, req);
      const order = ownedOrder(db, req);
      if (!order) return { error: "Order not found.", status: 404 };
      if (order.status !== "created") return { error: "A driver has already been requested.", status: 409 };
      order.status = "requested";
      order.requestedAt = new Date().toISOString();
      audit(db, { actorId: staff.id, action: "driver_requested", orderId: order.id, restaurantId: staff.restaurantId });
      matchWaiting(db, null);
      return { order: restaurantOrder(db, order) };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.post("/restaurant/orders/:id/cancel", auth("owner", "manager"), (req, res) => {
    const result = update((db) => {
      const order = ownedOrder(db, req);
      if (!order) return { error: "Order not found.", status: 404 };
      if (["delivered", "returned", "cancelled"].includes(order.status)) {
        return { error: "This order can no longer be cancelled.", status: 409 };
      }
      order.status = "cancelled";
      db.offers.forEach((offer) => {
        if (offer.orderId === order.id && offer.status === "pending") offer.status = "cancelled";
      });
      audit(db, { actorId: req.staff.id, action: "order_cancelled", orderId: order.id });
      return { order: restaurantOrder(db, order) };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.post("/restaurant/orders/:id/rate", auth("owner", "manager", "counter"), (req, res) => {
    const stars = Number(req.body.stars);
    if (!(stars >= 1 && stars <= 5)) return res.status(400).json({ error: "Choose a rating from 1 to 5." });
    const result = update((db) => {
      const order = ownedOrder(db, req);
      if (!order) return { error: "Order not found.", status: 404 };
      if (order.status !== "delivered") return { error: "Rate the driver after delivery.", status: 400 };
      order.rating = stars;
      audit(db, { actorId: req.staff.id, action: "driver_rated", orderId: order.id });
      return { order: restaurantOrder(db, order) };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.get("/restaurant/billing", auth("owner", "manager"), (req, res) => {
    const db = ensure();
    const rows = db.orders
      .filter((item) => item.restaurantId === req.staff.restaurantId && item.pay)
      .map((item) => ({
        id: item.id,
        at: item.createdAt,
        status: item.status,
        deliveryFee: item.pay.restaurantFee,
        last4: null,
      }));
    res.json({
      rows,
      total: rules.round(rows.reduce((sum, row) => sum + row.deliveryFee, 0)),
      note: "Card numbers are not stored. These are delivery fees only.",
    });
  });

  app.get("/restaurant/staff", auth("owner"), (req, res) => {
    const db = ensure();
    res.json({
      staff: db.staff
        .filter((item) => item.restaurantId === req.staff.restaurantId)
        .map((item) => ({ id: item.id, name: item.name, email: item.email, role: item.role, active: item.active })),
    });
  });

  app.post("/restaurant/staff", auth("owner"), (req, res) => {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").toLowerCase().trim();
    const role = req.body.role;
    if (!name || !email.includes("@")) return res.status(400).json({ error: "Name and email are required." });
    if (!["manager", "counter"].includes(role)) return res.status(400).json({ error: "Choose manager or counter staff." });
    const result = update((db) => {
      if (db.staff.some((item) => item.email === email)) return { error: "That email is already in use.", status: 409 };
      const person = {
        id: crypto.randomUUID(),
        restaurantId: req.staff.restaurantId,
        name,
        email,
        role,
        pinHash: bcrypt.hashSync("3333", 8),
        passwordHash: bcrypt.hashSync("PopDrivers123!", 8),
        sessionVersion: 1,
        active: true,
      };
      db.staff.push(person);
      audit(db, { actorId: req.staff.id, action: "staff_invited", targetId: person.id, role });
      return { staff: { id: person.id, name, email, role, temporaryPassword: "PopDrivers123!", pin: "3333" } };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.status(201).json(result);
  });

  app.delete("/restaurant/staff/:id", auth("owner"), (req, res) => {
    const result = update((db) => {
      const person = db.staff.find((item) => item.id === req.params.id && item.restaurantId === req.staff.restaurantId);
      if (!person) return { error: "Staff member not found.", status: 404 };
      if (person.role === "owner") return { error: "The owner account cannot be removed here.", status: 400 };
      person.active = false;
      person.sessionVersion += 1;
      audit(db, { actorId: req.staff.id, action: "staff_removed", targetId: person.id });
      return { ok: true };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.post("/restaurant/pos/connect", auth("owner"), (req, res) => {
    const provider = String(req.body.provider || "").slice(0, 40);
    if (!provider) return res.status(400).json({ error: "Choose the POS your restaurant uses." });
    const result = update((db) => {
      const restaurant = db.restaurants.find((item) => item.id === req.staff.restaurantId);
      restaurant.posConnected = true;
      restaurant.posProvider = provider;
      audit(db, { actorId: req.staff.id, action: "pos_connected", provider });
      return { posConnected: true, posProvider: provider };
    });
    res.json(result);
  });

  app.post("/pos/webhook", (req, res) => {
    const result = update((db) => {
      const restaurant = db.restaurants.find((item) => item.id === req.body.restaurantId);
      if (!restaurant) {
        audit(db, { actorId: "pos", action: "pos_unknown_restaurant" });
        return { error: "Unknown restaurant.", status: 404 };
      }
      const expected = crypto.createHmac("sha256", restaurant.posSecret).update(req.rawBody).digest("hex");
      const given = String(req.get("x-pop-signature") || "");
      if (!safeEqual(expected, given)) {
        audit(db, { actorId: "pos", action: "pos_bad_signature", restaurantId: restaurant.id });
        return { error: "Webhook could not be verified.", status: 401 };
      }
      const sentAt = new Date(req.body.sentAt).getTime();
      if (!sentAt || Math.abs(Date.now() - sentAt) > 5 * 60 * 1000) {
        return { error: "Webhook is too old.", status: 401 };
      }
      if (!req.body.nonce || db.nonces.includes(req.body.nonce)) {
        audit(db, { actorId: "pos", action: "pos_replay", restaurantId: restaurant.id });
        return { error: "Webhook was already used.", status: 409 };
      }
      db.nonces.push(req.body.nonce);
      const created = createOrder(db, { id: "pos", restaurantId: restaurant.id }, req.body);
      if (created.error) return created;
      created.order.source = "pos";
      audit(db, { actorId: "pos", action: "pos_order_imported", orderId: created.order.id, restaurantId: restaurant.id });
      return created;
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.status(201).json(result);
  });

  app.get("/track/:token", (req, res) => {
    const db = ensure();
    const order = db.orders.find((item) => item.trackingToken === req.params.token);
    if (!order || ["delivered", "cancelled", "returned"].includes(order.status)) {
      return res.status(404).send(trackPage("This tracking link has expired."));
    }
    const restaurant = restaurantById(db, order.restaurantId);
    const driver = db.drivers.find((item) => item.id === order.driverId);
    const payload = {
      restaurantName: restaurant.name,
      driverFirstName: driver ? driver.firstName : "A driver",
      status: order.status,
    };
    if (req.accepts(["html", "json"]) === "html") {
      return res.send(
        trackPage(
          `${payload.restaurantName}. Driver: ${payload.driverFirstName}. Status: ${payload.status}.`,
          order.trackingToken
        )
      );
    }
    res.json(payload);
  });

  app.get("/track/:token/thumb", (req, res) => {
    const vote = req.query.vote === "down" ? "down" : "up";
    const result = update((db) => {
      const order = db.orders.find((item) => item.trackingToken === req.params.token);
      if (!order || ["delivered", "cancelled", "returned"].includes(order.status)) {
        return { error: "This tracking link has expired.", status: 404 };
      }
      order.customerThumb = vote;
      audit(db, { actorId: "customer", action: "customer_thumb", orderId: order.id, note: vote });
      return { ok: true };
    });
    if (result.error) return res.status(result.status).send(trackPage(result.error));
    res.send(trackPage(vote === "up" ? "Thanks. The restaurant can see your thumbs-up." : "Thanks. Dispatch can see your thumbs-down."));
  });

  app.get("/admin", (_req, res) => {
    res.type("html").send(adminPage());
  });

  app.get("/admin/drivers", auth("admin"), (_req, res) => {
    const db = ensure();
    res.json({
      drivers: db.drivers.map((driver) => ({
        id: driver.id,
        name: driver.name,
        phoneLast4: String(driver.phone || "").slice(-4),
        status: driver.status,
        level: driver.level,
        lifetimeCompleted: driver.lifetimeCompleted,
      })),
    });
  });

  app.post("/admin/drivers/:id/approve", auth("admin"), (req, res) => {
    const result = update((db) => {
      const driver = db.drivers.find((item) => item.id === req.params.id);
      if (!driver) return { error: "Driver not found.", status: 404 };
      driver.status = "approved";
      audit(db, { actorId: req.user.sub, action: "driver_approved", targetId: driver.id });
      return { driver: { id: driver.id, status: driver.status } };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.post("/admin/drivers/:id/dispatch", auth("admin"), (req, res) => {
    const text = String(req.body.text || "").trim();
    if (text.length < 1) return res.status(400).json({ error: "Write a message first." });
    const result = update((db) => {
      const driver = db.drivers.find((item) => item.id === req.params.id);
      if (!driver) return { error: "Driver not found.", status: 404 };
      db.dispatchMessages = db.dispatchMessages || [];
      db.dispatchMessages.push({
        id: crypto.randomUUID(),
        driverId: driver.id,
        from: "dispatch",
        text: text.slice(0, 500),
        at: new Date().toISOString(),
      });
      audit(db, { actorId: req.user.sub, action: "dispatch_reply", targetId: driver.id });
      return { messages: chatFor(db, driver.id) };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.post("/admin/drivers/:id/level", auth("admin"), (req, res) => {
    const reason = String(req.body.reason || "").trim();
    const level = String(req.body.level || "");
    if (reason.length < 5) return res.status(400).json({ error: "A reason is required." });
    if (!Object.hasOwn(rules.LEVEL_RANK, level)) return res.status(400).json({ error: "Unknown level." });
    const result = update((db) => {
      const driver = db.drivers.find((item) => item.id === req.params.id);
      if (!driver) return { error: "Driver not found.", status: 404 };
      const from = driver.level;
      driver.level = level;
      db.levelEvents.push({
        id: crypto.randomUUID(),
        driverId: driver.id,
        from,
        to: level,
        reason: "admin",
        actorId: req.user.sub,
        note: reason,
        at: new Date().toISOString(),
      });
      audit(db, { actorId: req.user.sub, action: "level_override", targetId: driver.id });
      return { level };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  });

  app.get("/admin/audit", auth("admin"), (_req, res) => {
    const db = ensure();
    res.json({ audit: db.audit.slice(-50).reverse() });
  });

  app.use((req, res) => {
    if (req.path === "/admin") return res.redirect("/admin/");
    res.status(404).json({ error: "Not found." });
  });

  app.use((err, _req, res, _next) => {
    console.error(err);
    res.status(500).json({ error: "Something went wrong." });
  });

  return app;

  function auth(...roles) {
    return (req, res, next) => {
      const header = req.get("authorization") || "";
      const token = header.startsWith("Bearer ") ? header.slice(7) : "";
      let payload;
      try {
        payload = jwt.verify(token, SECRET);
      } catch {
        return res.status(401).json({ error: "Please sign in again." });
      }
      const db = ensure();
      if (payload.role === "driver") {
        const driver = db.drivers.find((item) => item.id === payload.sub);
        if (!driver || driver.sessionVersion !== payload.sv) {
          return res.status(401).json({ error: "This phone was signed out." });
        }
        req.user = payload;
        req.driver = driver;
      } else if (payload.role === "admin") {
        const admin = db.admins.find((item) => item.id === payload.sub);
        if (!admin || admin.sessionVersion !== payload.sv) return res.status(401).json({ error: "Please sign in again." });
        req.user = payload;
      } else {
        const person = db.staff.find((item) => item.id === payload.sub && item.active);
        if (!person || person.sessionVersion !== payload.sv) {
          return res.status(401).json({ error: "This sign-in has ended." });
        }
        req.user = payload;
        req.staff = person;
      }
      if (roles.length && !roles.includes(req.user.role)) {
        return res.status(403).json({ error: "You cannot do that." });
      }
      next();
    };
  }
}

function signToken(payload) {
  return jwt.sign(payload, SECRET, { expiresIn: "12h" });
}

function driverToken(driver) {
  return { sub: driver.id, role: "driver", sv: driver.sessionVersion };
}

function staffToken(person) {
  return { sub: person.id, role: person.role, sv: person.sessionVersion, restaurantId: person.restaurantId };
}

function fresh(db, req) {
  return db.drivers.find((item) => item.id === req.driver.id);
}

function freshStaff(db, req) {
  return db.staff.find((item) => item.id === req.staff.id);
}

function normalizePhone(value) {
  const digits = String(value || "").replace(/[^\d+]/g, "");
  if (digits.replace(/\D/g, "").length < 10) return "";
  return digits.startsWith("+") ? digits : `+${digits}`;
}

function restaurantPasswordError(password) {
  if (password.length < 12) return "Use a password of at least 12 characters.";
  if (password.toLowerCase() === "password123456") return "Choose a password that is not a known breach.";
  return "";
}

function normalizeEmail(value) {
  const email = String(value || "").toLowerCase().trim();
  if (!email.includes("@") || email.startsWith("@") || email.endsWith("@")) return "";
  return email;
}

function placeholderPhone(db) {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const phone = `+1555${crypto.randomInt(1000000, 9999999)}`;
    if (!db.drivers.some((item) => item.phone === phone)) return phone;
  }
  return `+1${Date.now()}`;
}

function newDriver(phone) {
  return {
    id: crypto.randomUUID(),
    name: "New driver",
    firstName: "New",
    phone,
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
    preferences: { maxDistance: 8, alcoholOk: true, largeOk: true, zones: [] },
    documents: [],
    trainingComplete: false,
    location: { lat: 37.7749, lng: -122.4194 },
  };
}

function publicDriver(driver) {
  return {
    id: driver.id,
    name: driver.name,
    firstName: driver.firstName,
    phone: driver.phone,
    phoneLast4: String(driver.phone || "").slice(-4),
    email: driver.email || "",
    status: driver.status,
    level: driver.level,
    lifetimeCompleted: driver.lifetimeCompleted,
    online: driver.online,
    vehicle: driver.vehicle,
    bankLast4: driver.bankLast4,
    pendingPayout: driver.pendingPayout,
    photoRecheck: driver.photoRecheck,
    trainingComplete: driver.trainingComplete,
  };
}

function publicStaff(person, db) {
  const restaurant = db.restaurants.find((item) => item.id === person.restaurantId);
  return {
    id: person.id,
    name: person.name,
    role: person.role,
    restaurantId: person.restaurantId,
    restaurantName: restaurant.name,
    posConnected: restaurant.posConnected,
    posProvider: restaurant.posProvider,
  };
}

function publicLevel(driver, db, rolling) {
  const events = db && db.levelEvents ? db.levelEvents.filter((item) => item.driverId === driver.id) : [];
  return {
    level: driver.level,
    lifetimeCompleted: driver.lifetimeCompleted,
    next: rules.nextLevel(driver.lifetimeCompleted),
    paused: Boolean(driver.paused),
    atRiskSince: driver.atRiskSince || null,
    advisorySeat: driver.level === "diamond",
    rolling: rolling || null,
    history: events.slice(-8).reverse(),
    quality: {
      ratingAvg: driver.ratingAvg,
      ratingCount: driver.ratingCount,
      onTimePct: driver.onTimePct,
      cancelPct: driver.cancelPct,
      status: driver.qualityStatus,
    },
    acceptanceRateUsed: false,
    rewards: rewardsFor(driver.level),
  };
}

function rewardsFor(level) {
  const all = [
    ["starter", "Full pay, 100% of tips, Thursday payout"],
    ["bronze", "Badge, cap and bag, cheaper instant cash-out"],
    ["silver", "Book shifts 24 hours early, 2 free instant cash-outs a week"],
    ["gold", "Book shifts 48 hours early, first look at open requests, free instant cash-out"],
    ["platinum", "Extra $0.25 per delivery and up to 3 favorite restaurants"],
    ["diamond", "Extra $0.50 per delivery, a $2 mentoring bonus, and a driver advisory seat"],
  ];
  const rank = rules.LEVEL_RANK[level];
  return all.filter((_, index) => index <= rank).map((item) => item[1]);
}

function documentViews(driver) {
  return (driver.documents || []).map((doc) => {
    const days = Math.ceil((new Date(doc.expiresAt).getTime() - Date.now()) / (24 * 60 * 60 * 1000));
    return { ...doc, daysLeft: days, reminder: days <= 30 };
  });
}

function expiredDoc(driver) {
  if (driver.vehicle === "bicycle") return false;
  return (driver.documents || []).some((doc) => new Date(doc.expiresAt).getTime() < Date.now());
}

function point(body) {
  const lat = Number(body?.lat);
  const lng = Number(body?.lng);
  if (!Number.isFinite(lat) || !Number.isFinite(lng)) return null;
  const speed = Number(body?.speedMph || 0);
  if (speed > 90) return null;
  return { lat, lng };
}

function restaurantById(db, id) {
  return db.restaurants.find((item) => item.id === id);
}

function allows(driver, order) {
  const prefs = driver.preferences;
  if (order.distanceMiles > prefs.maxDistance) return false;
  if (order.alcohol && !prefs.alcoholOk) return false;
  if (order.large && !prefs.largeOk) return false;
  if (prefs.zones.length && !prefs.zones.includes(order.zone)) return false;
  if (driver.status !== "approved" || expiredDoc(driver)) return false;
  return true;
}

function expireOffers(db) {
  const now = Date.now();
  db.offers.forEach((offer) => {
    if (offer.status === "pending" && new Date(offer.expiresAt).getTime() <= now) offer.status = "expired";
  });
}

function matchWaiting(db, preferred) {
  expireOffers(db);
  const waiting = db.orders
    .filter((order) => order.status === "requested" && !order.driverId)
    .filter((order) => !db.offers.some((offer) => offer.orderId === order.id && offer.status === "pending"));
  let created = null;
  for (const order of waiting) {
    const pool = db.drivers.filter(
      (driver) =>
        driver.online &&
        allows(driver, order) &&
        !(order.declines || []).includes(driver.id) &&
        rules.canSeeOpenRequest(driver.level, order.requestedAt)
    );
    pool.sort((a, b) => {
      const rank = rules.LEVEL_RANK[b.level] - rules.LEVEL_RANK[a.level];
      if (rank) return rank;
      const favorite = (person) => ((person.preferences && person.preferences.favorites) || []).includes(order.restaurantId) ? 1 : 0;
      return favorite(b) - favorite(a);
    });
    const chosen = preferred && pool.some((driver) => driver.id === preferred.id) ? preferred : pool[0];
    if (!chosen) continue;
    if (db.offers.some((offer) => offer.driverId === chosen.id && offer.status === "pending")) continue;
    const offer = {
      id: crypto.randomUUID(),
      orderId: order.id,
      driverId: chosen.id,
      status: "pending",
      expiresAt: new Date(Date.now() + 30 * 1000).toISOString(),
    };
    db.offers.push(offer);
    if (preferred && chosen.id === preferred.id) created = offer;
  }
  return created;
}

function acceptOffer(db, driver, offerId) {
  expireOffers(db);
  const offer = db.offers.find((item) => item.id === offerId);
  if (!offer || offer.status !== "pending" || offer.driverId !== driver.id) {
    return { error: "That offer is no longer available.", status: 409 };
  }
  const order = db.orders.find((item) => item.id === offer.orderId);
  if (!order || order.driverId || order.status !== "requested") {
    offer.status = "expired";
    return { error: "That delivery was already taken.", status: 409 };
  }
  if (!allows(driver, order)) return { error: "This delivery is outside your preferences.", status: 403 };
  offer.status = "accepted";
  order.driverId = driver.id;
  order.status = "accepted";
  if (order.pay.levelBonus == null) {
    order.pay.levelBonus = rules.levelBonus(driver.level);
    order.pay.driverTotal = rules.round(order.pay.driverTotal + order.pay.levelBonus);
  }
  db.offers.forEach((item) => {
    if (item.orderId === order.id && item.id !== offer.id && item.status === "pending") item.status = "cancelled";
  });
  audit(db, { actorId: driver.id, action: "offer_accepted", orderId: order.id });
  return { delivery: driverView(db, order, true) };
}

function openRequestsFor(db, driver) {
  return db.orders
    .filter((order) => order.status === "requested" && !order.driverId)
    .filter((order) => !db.offers.some((offer) => offer.orderId === order.id && offer.status === "pending"))
    .filter((order) => rules.canSeeOpenRequest(driver.level, order.requestedAt))
    .filter((order) => allows(driver, order))
    .map((order) => ({
      orderId: order.id,
      ...driverView(db, order, false, driver),
    }));
}

function offerPayload(db, offer) {
  const order = db.orders.find((item) => item.id === offer.orderId);
  const driver = db.drivers.find((item) => item.id === offer.driverId);
  return {
    offerId: offer.id,
    expiresAt: offer.expiresAt,
    order: driverView(db, order, false, driver),
  };
}

function payFor(order, driver) {
  if (!driver) return order.pay;
  const bonus = rules.levelBonus(driver.level);
  const already = Number(order.pay.levelBonus || 0);
  const extra = Math.max(0, rules.round(bonus - already));
  return {
    ...order.pay,
    levelBonus: Math.max(already, bonus),
    driverTotal: rules.round(order.pay.driverTotal + extra),
  };
}

function driverView(db, order, active, driver) {
  const restaurant = restaurantById(db, order.restaurantId);
  const revealed = active && ["picked_up", "waiting_customer", "delivered", "returned"].includes(order.status);
  const view = {
    id: order.id,
    status: order.status,
    restaurantName: restaurant.name,
    restaurantAddress: restaurant.address,
    stop: revealed
      ? { label: order.address, point: order.dropoff }
      : { label: restaurant.name, point: order.restaurantLocation, area: order.area },
    area: order.area,
    bags: order.bags,
    alcohol: order.alcohol,
    large: order.large,
    readyAt: order.readyAt,
    distanceMiles: order.distanceMiles,
    estimatedMinutes: rules.estimateMinutes(order.distanceMiles),
    pay: payFor(order, driver),
    kitchenLate: Boolean(order.kitchenLate),
    notes: revealed ? order.notes : undefined,
    customerFirstName: revealed ? order.customerName.split(" ")[0] : undefined,
    pinRequired: Boolean(order.alcohol),
  };
  if (["delivered", "returned", "cancelled"].includes(order.status)) {
    delete view.notes;
    delete view.customerFirstName;
    view.stop = { label: "Address hidden after delivery", point: null };
    view.area = "Hidden";
  }
  return view;
}

function chatFor(db, driverId) {
  return (db.dispatchMessages || [])
    .filter((item) => item.driverId === driverId)
    .sort((a, b) => new Date(a.at) - new Date(b.at))
    .map((item) => ({ id: item.id, from: item.from, text: item.text, at: item.at }));
}

function activeOrder(db, driverId) {
  return db.orders.find(
    (order) =>
      order.driverId === driverId &&
      ["accepted", "at_pickup", "picked_up", "waiting_customer"].includes(order.status)
  );
}

function mustActive(db, driverId) {
  return activeOrder(db, driverId) || { error: "No active delivery.", status: 404 };
}

function createOrder(db, actor, body) {
  const address = String(body.address || "").trim();
  const customerName = String(body.customerName || "").trim();
  const phone = String(body.phone || "").replace(/\D/g, "");
  if (customerName.length < 2 || address.length < 5 || phone.length < 10) {
    return { error: "Customer name, phone, and address are required.", status: 400 };
  }
  const restaurant = restaurantById(db, actor.restaurantId);
  const distanceMiles = rules.distanceMilesForAddress(address);
  const tip = rules.round(Math.max(0, Number(body.tip) || 0));
  const alcohol = Boolean(body.alcohol);
  const large = Boolean(body.large) || Number(body.bags) >= 6;
  const pay = rules.quoteDelivery({
    distanceMiles,
    tip,
    alcohol,
    large,
    rush: Boolean(body.rush),
  });
  const readyMinutes = Math.min(180, Math.max(0, Number(body.readyInMinutes) || 15));
  const order = {
    id: crypto.randomUUID(),
    restaurantId: restaurant.id,
    customerName: customerName.slice(0, 80),
    phone,
    address: address.slice(0, 160),
    area: rules.areaFromAddress(address),
    notes: String(body.notes || "").slice(0, 240),
    bags: Math.min(20, Math.max(1, Number(body.bags) || 1)),
    alcohol,
    large,
    tip,
    readyAt: body.readyAt || new Date(Date.now() + readyMinutes * 60 * 1000).toISOString(),
    distanceMiles,
    zone: restaurant.zone,
    status: "created",
    driverId: null,
    pay,
    proof: null,
    pin: alcohol ? String(crypto.randomInt(1000, 9999)) : null,
    trackingToken: crypto.randomBytes(24).toString("hex"),
    createdAt: new Date().toISOString(),
    requestedAt: null,
    restaurantLocation: restaurant.location,
    dropoff: { lat: restaurant.location.lat - 0.02, lng: restaurant.location.lng - 0.02 },
    declines: [],
    rating: null,
    locationChecks: { pickup: false, dropoff: false },
    countedForLevel: false,
    source: actor.id === "pos" ? "pos" : "app",
  };
  db.orders.push(order);
  audit(db, { actorId: actor.id, action: "order_created", orderId: order.id, restaurantId: restaurant.id });
  return { order: restaurantOrder(db, order) };
}

function ownedOrder(db, req) {
  return db.orders.find((item) => item.id === req.params.id && item.restaurantId === req.staff.restaurantId);
}

function restaurantOrder(db, order) {
  const driver = db.drivers.find((item) => item.id === order.driverId);
  return {
    id: order.id,
    status: order.status,
    customerName: order.customerName,
    phone: order.phone,
    address: order.address,
    area: order.area,
    notes: order.notes,
    bags: order.bags,
    alcohol: order.alcohol,
    large: order.large,
    tip: order.tip,
    readyAt: order.readyAt,
    distanceMiles: order.distanceMiles,
    pay: order.pay,
    pin: order.pin,
    trackingPath: `/track/${order.trackingToken}`,
    driverFirstName: driver ? driver.firstName : null,
    rating: order.rating,
    source: order.source || "app",
    createdAt: order.createdAt,
  };
}

function shiftView(shift, driver, db) {
  const lead = rules.shiftLeadHours(driver.level);
  const opens = new Date(new Date(shift.start).getTime() - lead * 60 * 60 * 1000);
  const restaurant = restaurantById(db, shift.restaurantId);
  return {
    id: shift.id,
    restaurantName: restaurant.name,
    start: shift.start,
    end: shift.end,
    hourlyGuarantee: shift.hourlyGuarantee,
    bookedByMe: shift.bookedBy === driver.id,
    booked: Boolean(shift.bookedBy),
    open: lead > 0 && Date.now() >= opens.getTime() && !shift.bookedBy,
    opensAt: lead ? opens.toISOString() : null,
    leadHours: lead,
  };
}

function audit(db, entry) {
  db.audit.push({ id: crypto.randomUUID(), at: new Date().toISOString(), ...entry });
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function titleCase(value) {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function daysFromNow(days) {
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
}

function adminPage() {
  return `<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pop-Drivers dispatch</title>
<style>body{font-family:Georgia,serif;background:#f3f0e8;color:#1c2b24;margin:0;padding:32px}button,input{font:inherit;padding:8px 12px;margin:4px 0}table{border-collapse:collapse;width:100%;background:#fffdf8}td,th{border-bottom:1px solid #e4ddd0;text-align:left;padding:8px}</style></head>
<body><h1>Dispatch</h1><p>Approve drivers and record a reason for any level change.</p>
<div id="login"><input id="email" value="admin@popdrivers.example"><br><input id="password" type="password" value="PopDrivers123!"><br><button id="go">Sign in</button></div>
<div id="app" hidden><button id="out">Sign out</button><h2>Drivers</h2><table id="rows"></table><h2>Recent activity</h2><pre id="log"></pre></div>
<script>
let token = sessionStorage.getItem('pop_admin') || '';
const api = (path, opts={}) => fetch(path, { ...opts, headers: { 'Content-Type':'application/json', ...(token?{Authorization:'Bearer '+token}:{}) , ...(opts.headers||{}) }, body: opts.body ? JSON.stringify(opts.body) : undefined }).then(async r => { const d = await r.json(); if(!r.ok) throw new Error(d.error||'Error'); return d; });
async function show(){ if(!token) return; document.getElementById('login').hidden = true; document.getElementById('app').hidden = false; const data = await api('/admin/drivers'); const audit = await api('/admin/audit'); document.getElementById('rows').innerHTML = '<tr><th>Name</th><th>Status</th><th>Level</th><th></th></tr>' + data.drivers.map(d => '<tr><td>'+d.name+'</td><td>'+d.status+'</td><td>'+d.level+' · '+d.lifetimeCompleted+'</td><td><button data-reply="'+d.id+'">Reply</button>'+(d.status!=='approved'?' <button data-id="'+d.id+'">Approve</button>':'')+'</td></tr>').join(''); document.getElementById('log').textContent = audit.audit.map(a => a.at+' '+a.action).join('\\n'); document.querySelectorAll('button[data-id]').forEach(btn => btn.onclick = async () => { await api('/admin/drivers/'+btn.dataset.id+'/approve', { method:'POST', body:{} }); show(); }); document.querySelectorAll('button[data-reply]').forEach(btn => btn.onclick = async () => { const text = prompt('Message to this driver'); if (!text) return; await api('/admin/drivers/'+btn.dataset.reply+'/dispatch', { method:'POST', body:{ text } }); }); }
document.getElementById('go').onclick = async () => { const data = await api('/auth/admin/login', { method:'POST', body:{ email: email.value, password: password.value } }); token = data.token; sessionStorage.setItem('pop_admin', token); show(); };
document.getElementById('out').onclick = () => { token=''; sessionStorage.removeItem('pop_admin'); location.reload(); };
if (token) show();
</script></body></html>`;
}

function trackPage(message, token) {
  const safe = String(message).replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
  const buttons = token
    ? `<p><a href="/track/${token}/thumb?vote=up">Thumbs up</a> · <a href="/track/${token}/thumb?vote=down">Thumbs down</a></p>`
    : "";
  return `<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pop-Drivers tracking</title></head><body style="font-family:Georgia,serif;background:#f3f0e8;color:#1c2b24;padding:32px"><h1>Pop-Drivers</h1><p>${safe}</p>${buttons}</body></html>`;
}

function preferenceView(db, driver) {
  const zoneChoices = [...new Set((db.restaurants || []).map((item) => item.zone).filter(Boolean))];
  return {
    ...driver.preferences,
    favorites: driver.preferences.favorites || [],
    zones: driver.preferences.zones || [],
    vehicle: driver.vehicle,
    zoneChoices,
  };
}

function qualityLines(db, driver, now = Date.now()) {
  const start = now - 90 * 24 * 60 * 60 * 1000;
  const recent = db.orders.filter((order) => order.driverId === driver.id && new Date(order.deliveredAt || order.createdAt).getTime() >= start);
  const name = (order) => restaurantById(db, order.restaurantId).name;
  const ratings = recent
    .filter((order) => Number(order.rating) >= 1)
    .map((order) => ({ id: order.id, restaurantName: name(order), rating: order.rating, at: order.deliveredAt || order.createdAt }));
  const latePickups = recent
    .filter((order) => order.status === "delivered" && !order.kitchenLate && order.arrivedAt && order.readyAt)
    .filter((order) => new Date(order.arrivedAt).getTime() - new Date(order.readyAt).getTime() > 5 * 60 * 1000)
    .map((order) => ({
      id: order.id,
      restaurantName: name(order),
      minutesLate: Math.round((new Date(order.arrivedAt).getTime() - new Date(order.readyAt).getTime()) / 60000),
      at: order.deliveredAt || order.arrivedAt,
    }));
  return { ratings, latePickups };
}

function applyMonthlyReview(db, now = new Date()) {
  if (!rules.isMonthlyReviewDay(now)) return { ran: false, reason: "Quality is reviewed on the 1st of each month." };
  const period = now.toISOString().slice(0, 7);
  if (db.lastQualityReview === period) return { ran: false, reason: "This month was already reviewed.", period };
  let changes = 0;
  for (const driver of db.drivers) {
    const next = rules.standing(driver, db.orders, now.getTime());
    driver.level = next.level;
    driver.atRiskSince = next.atRiskSince;
    driver.paused = next.paused;
    driver.pausedAt = next.pausedAt;
    driver.qualityStatus = next.quality.status;
    driver.ratingAvg = next.quality.ratingCount ? next.quality.ratingAvg : driver.ratingAvg;
    driver.ratingCount = next.quality.ratingCount || driver.ratingCount;
    driver.onTimePct = next.quality.onTimePct;
    driver.cancelPct = next.quality.cancelPct;
    if (!db.qualitySnapshots.some((item) => item.driverId === driver.id && item.period === period)) {
      db.qualitySnapshots.push({ driverId: driver.id, period, ...next.quality, at: now.toISOString() });
    }
    if (next.event) {
      changes += 1;
      db.levelEvents.push({
        id: crypto.randomUUID(),
        driverId: driver.id,
        from: next.event.from,
        to: next.event.to,
        reason: next.event.reason,
        actorId: "server",
        note: next.event.note,
        at: now.toISOString(),
      });
      db.inbox.push({
        id: crypto.randomUUID(),
        driverId: driver.id,
        title: "Level review",
        body: next.event.note,
        at: now.toISOString(),
      });
    }
  }
  db.lastQualityReview = period;
  return { ran: true, period, changes };
}

if (require.main === module) {
  const port = Number(process.env.PORT || 4000);
  const app = createApp();
  const review = () => {
    try {
      update((db) => applyMonthlyReview(db, new Date()));
    } catch (error) {
      console.error(error);
    }
  };
  review();
  const timer = setInterval(review, 60 * 60 * 1000);
  if (timer.unref) timer.unref();
  app.listen(port, () => {
    console.log(`Pop-Drivers API listening on http://localhost:${port}`);
  });
}

module.exports = { createApp };
