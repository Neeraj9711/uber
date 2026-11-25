const assert = require("assert");
const rules = require("../src/rules");

const cheap = rules.quoteDelivery({ distanceMiles: 0.4, tip: 2 });
assert.strictEqual(cheap.restaurantFee, 6.5);
assert.strictEqual(cheap.tip, 2);
assert.ok(cheap.driverTotal >= 2);

const oak = rules.quoteDelivery({ distanceMiles: 2.2, tip: 4 });
assert.strictEqual(oak.restaurantFee, 7.25);
assert.strictEqual(oak.driverTotal, 9.26);
assert.notStrictEqual(oak.restaurantFee, rules.round(15 * 0.15));

assert.strictEqual(rules.levelFor(49), "starter");
assert.strictEqual(rules.levelFor(50), "bronze");
assert.strictEqual(rules.levelFor(100), "silver");
assert.strictEqual(rules.levelFor(150), "gold");
assert.strictEqual(rules.levelFor(300), "platinum");
assert.strictEqual(rules.levelFor(500), "diamond");
assert.strictEqual(rules.nextLevel(112).remaining, 38);

assert.strictEqual(rules.canSeeOpenRequest("gold", new Date().toISOString()), true);
assert.strictEqual(rules.canSeeOpenRequest("silver", new Date().toISOString()), false);
assert.strictEqual(
  rules.canSeeOpenRequest("starter", new Date(Date.now() - 11000).toISOString()),
  true
);
assert.strictEqual(rules.shiftLeadHours("starter"), 0);
assert.strictEqual(rules.shiftLeadHours("silver"), 24);
assert.strictEqual(rules.shiftLeadHours("gold"), 48);
assert.strictEqual(rules.cashOutFee("gold", 0), 0);
assert.strictEqual(rules.cashOutFee("silver", 2), 0.75);

const here = { lat: 37.77, lng: -122.42 };
assert.strictEqual(rules.near(here, { lat: 37.7701, lng: -122.4201 }), true);
assert.strictEqual(rules.near(here, { lat: 0, lng: 0 }), false);

assert.strictEqual(rules.levelBonus("silver"), 0);
assert.strictEqual(rules.levelBonus("platinum"), 0.25);
assert.strictEqual(rules.levelBonus("diamond"), 0.5);
assert.strictEqual(rules.mentorBonus("diamond"), 2);
assert.strictEqual(rules.deviceProblem({ mocked: true }), "A mock location can't be used.");
assert.strictEqual(rules.deviceProblem({ rooted: true }).includes("rooted"), true);

const now = Date.now();
const weak = rules.standing(
  { id: "d1", level: "gold", atRiskSince: new Date(now - 31 * 24 * 60 * 60 * 1000).toISOString(), paused: false },
  Array.from({ length: 6 }, (_, index) => ({
    driverId: "d1",
    status: "delivered",
    deliveredAt: new Date(now - 2 * 24 * 60 * 60 * 1000).toISOString(),
    arrivedAt: new Date(now - 2 * 24 * 60 * 60 * 1000).toISOString(),
    readyAt: new Date(now - 2 * 24 * 60 * 60 * 1000 - 20 * 60 * 1000).toISOString(),
    kitchenLate: false,
    rating: index < 20 ? 3 : 5,
  })),
  now
);
assert.strictEqual(weak.quality.status, "at_risk");
assert.strictEqual(weak.level, "silver");
assert.strictEqual(weak.event.reason, "quality");

const idle = rules.standing(
  { id: "d2", level: "silver", paused: false },
  [{ driverId: "d2", status: "delivered", deliveredAt: new Date(now - 100 * 24 * 60 * 60 * 1000).toISOString() }],
  now
);
assert.strictEqual(idle.paused, true);
assert.strictEqual(idle.event.reason, "inactivity");

const split = rules.earningsSplit([
  { at: new Date().toISOString(), pay: { driverTotal: 9.26 }, distanceMiles: 2.2, returnPay: 0 },
]);
assert.strictEqual(split.today, 9.26);
assert.strictEqual(split.week, 9.26);
assert.strictEqual(split.miles, 2.2);

assert.strictEqual(rules.versionBelow("0.9.0", "1.0.0"), true);
assert.strictEqual(rules.versionBelow("1.0.0", "1.0.0"), false);
assert.strictEqual(rules.inRollout("phone", 100), true);

console.log("rules ok");
