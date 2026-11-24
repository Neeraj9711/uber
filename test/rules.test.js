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

console.log("rules ok");
