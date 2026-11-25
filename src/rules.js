function round(n) {
  return Math.round((Number(n) || 0) * 100) / 100;
}

function levelFor(count) {
  const completed = Number(count) || 0;
  if (completed >= 500) return "diamond";
  if (completed >= 300) return "platinum";
  if (completed >= 150) return "gold";
  if (completed >= 100) return "silver";
  if (completed >= 50) return "bronze";
  return "starter";
}

const LEVEL_RANK = {
  starter: 0,
  bronze: 1,
  silver: 2,
  gold: 3,
  platinum: 4,
  diamond: 5,
};

const NEXT_LEVEL = [
  { at: 50, name: "bronze" },
  { at: 100, name: "silver" },
  { at: 150, name: "gold" },
  { at: 300, name: "platinum" },
  { at: 500, name: "diamond" },
];

function nextLevel(count) {
  const completed = Number(count) || 0;
  let from = 0;
  for (const step of NEXT_LEVEL) {
    if (completed < step.at) {
      return { name: step.name, at: step.at, remaining: step.at - completed, from };
    }
    from = step.at;
  }
  return { name: "diamond", at: 500, remaining: 0, from: 500 };
}

function estimateMinutes(distanceMiles) {
  const miles = Math.max(0, Number(distanceMiles) || 0);
  return Math.max(12, Math.round((miles / 18) * 60 + 10));
}

function quoteDelivery({ distanceMiles, tip = 0, alcohol = false, large = false, rush = false }) {
  const miles = Math.max(0, Number(distanceMiles) || 0);
  const safeTip = round(Math.max(0, Number(tip) || 0));
  let restaurantFee = 4.5 + 1.25 * miles;
  if (restaurantFee < 6.5) restaurantFee = 6.5;
  if (alcohol) restaurantFee += 1;
  if (large) restaurantFee += 2;
  if (rush) restaurantFee += 1;
  const driverBase = 3.5;
  const driverMiles = round(0.8 * miles);
  const boost = rush ? 1 : 0;
  const driverTotal = round(driverBase + driverMiles + boost + safeTip);
  return {
    distanceMiles: round(miles),
    restaurantFee: round(restaurantFee),
    driverBase,
    driverMiles,
    wait: 0,
    boost,
    tip: safeTip,
    driverTotal,
  };
}

function distanceMilesForAddress(address) {
  const text = String(address || "").toLowerCase();
  if (text.includes("oak")) return 2.2;
  if (text.includes("market")) return 1.1;
  if (text.includes("mission")) return 3.4;
  if (text.includes("sunset")) return 4.8;
  return 2.5;
}

function areaFromAddress(address) {
  const parts = String(address || "")
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
  if (parts.length >= 2) return parts.slice(1).join(", ");
  return "Nearby area";
}

function haversineMiles(a, b) {
  if (!a || !b || a.lat == null || b.lat == null) return Infinity;
  const earth = 3958.8;
  const dLat = ((b.lat - a.lat) * Math.PI) / 180;
  const dLng = ((b.lng - a.lng) * Math.PI) / 180;
  const lat1 = (a.lat * Math.PI) / 180;
  const lat2 = (b.lat * Math.PI) / 180;
  const h =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLng / 2) ** 2;
  return 2 * earth * Math.asin(Math.min(1, Math.sqrt(h)));
}

function near(point, target, miles = 0.15) {
  return haversineMiles(point, target) <= miles;
}

function canSeeOpenRequest(level, requestedAt, now = Date.now()) {
  if (["gold", "platinum", "diamond"].includes(level)) return true;
  return now - new Date(requestedAt).getTime() >= 10 * 1000;
}

function shiftLeadHours(level) {
  if (["gold", "platinum", "diamond"].includes(level)) return 48;
  if (level === "silver") return 24;
  return 0;
}

function cashOutFee(level, freeUsed) {
  if (["gold", "platinum", "diamond"].includes(level)) return 0;
  if (level === "silver" && freeUsed < 2) return 0;
  if (level === "bronze") return 0.75;
  if (level === "silver") return 0.75;
  return 1.5;
}

function levelBonus(level) {
  if (level === "diamond") return 0.5;
  if (level === "platinum") return 0.25;
  return 0;
}

function mentorBonus(level) {
  return level === "diamond" ? 2 : 0;
}

function deviceProblem(body) {
  const source = body || {};
  const location = source.location || {};
  if (source.mocked || location.mocked) return "A mock location can't be used.";
  if (source.rooted || location.rooted) return "A rooted phone can't go online.";
  if (source.jailbroken || location.jailbroken) return "A jailbroken phone can't go online.";
  return "";
}

const DAY = 24 * 60 * 60 * 1000;
const LEVEL_ORDER = ["starter", "bronze", "silver", "gold", "platinum", "diamond"];

function previousLevel(level) {
  const index = LEVEL_ORDER.indexOf(level);
  if (index <= 0) return "starter";
  return LEVEL_ORDER[index - 1];
}

function reviewQuality(driver, orders, now = Date.now()) {
  const start = now - 90 * DAY;
  const recent = (orders || []).filter((order) => order.driverId === driver.id && new Date(order.deliveredAt || order.createdAt).getTime() >= start);
  const rated = recent.filter((order) => Number(order.rating) >= 1);
  const ratingCount = rated.length;
  const ratingAvg = ratingCount ? round(rated.reduce((sum, order) => sum + Number(order.rating), 0) / ratingCount) : 0;
  const timed = recent.filter((order) => order.status === "delivered" && !order.kitchenLate && order.arrivedAt && order.readyAt);
  const onTime = timed.filter((order) => new Date(order.arrivedAt).getTime() - new Date(order.readyAt).getTime() <= 5 * 60 * 1000);
  const onTimePct = timed.length ? Math.round((100 * onTime.length) / timed.length) : 100;
  const finished = recent.filter((order) => ["delivered", "cancelled", "returned"].includes(order.status));
  const driverCancels = finished.filter((order) => order.status === "cancelled" && order.cancelledBy === "driver");
  const cancelPct = finished.length ? Math.round((100 * driverCancels.length) / finished.length) : 0;
  const ratingFails = ratingCount >= 20 && ratingAvg < 4.8;
  const onTimeFails = timed.length >= 5 && onTimePct < 90;
  const cancelFails = finished.length >= 5 && cancelPct > 5;
  return {
    ratingAvg,
    ratingCount,
    onTimePct,
    cancelPct,
    status: ratingFails || onTimeFails || cancelFails ? "at_risk" : "ok",
  };
}

function isMonthlyReviewDay(now = new Date()) {
  return now.getDate() === 1;
}

function standing(driver, orders, now = Date.now()) {
  const quality = reviewQuality(driver, orders, now);
  let level = driver.level;
  let atRiskSince = driver.atRiskSince || null;
  let paused = Boolean(driver.paused);
  let pausedAt = driver.pausedAt || null;
  let event = null;
  const delivered = (orders || []).filter((order) => order.driverId === driver.id && order.status === "delivered" && order.deliveredAt);
  const last = delivered.reduce((max, order) => Math.max(max, new Date(order.deliveredAt).getTime()), 0);
  if (last && now - last >= 90 * DAY && !paused) {
    paused = true;
    pausedAt = new Date(now).toISOString();
    event = { from: level, to: level, reason: "inactivity", note: "No deliveries for 90 days" };
  }
  const sincePause = pausedAt ? delivered.filter((order) => new Date(order.deliveredAt).getTime() >= new Date(pausedAt).getTime()).length : 0;
  if (paused && sincePause >= 10 && quality.status === "ok") {
    paused = false;
    pausedAt = null;
    event = { from: level, to: level, reason: "returned", note: "10 deliveries after a pause" };
  }
  if (quality.status === "at_risk") {
    if (!atRiskSince) atRiskSince = new Date(now).toISOString();
    else if (now - new Date(atRiskSince).getTime() >= 30 * DAY && level !== "starter") {
      const from = level;
      level = previousLevel(level);
      atRiskSince = null;
      event = { from, to: level, reason: "quality", note: "Below the 90-day standard after 30 days at risk" };
    }
  } else if (!paused) {
    atRiskSince = null;
  }
  return { level, quality, atRiskSince, paused, pausedAt, event };
}

function earningsSplit(rows, now = new Date()) {
  const day = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  const weekStart = new Date(now.getFullYear(), now.getMonth(), now.getDate() - now.getDay()).getTime();
  let today = 0;
  let week = 0;
  let miles = 0;
  const older = new Map();
  for (const row of rows) {
    const at = new Date(row.at).getTime();
    const amount = round((row.pay?.driverTotal || 0) + (row.returnPay || 0));
    miles = round(miles + Number(row.distanceMiles || 0));
    if (at >= day) today = round(today + amount);
    if (at >= weekStart) week = round(week + amount);
    else {
      const date = new Date(at);
      const label = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}`;
      older.set(label, round((older.get(label) || 0) + amount));
    }
  }
  return { today, week, miles, pastWeeks: [...older.entries()].map(([label, total]) => ({ label, total })) };
}

function versionBelow(client, minimum) {
  const parse = (value) => String(value || "0").split(".").map((part) => parseInt(part, 10) || 0);
  const left = parse(client);
  const right = parse(minimum);
  for (let index = 0; index < 3; index += 1) {
    if ((left[index] || 0) < (right[index] || 0)) return true;
    if ((left[index] || 0) > (right[index] || 0)) return false;
  }
  return false;
}

function inRollout(deviceId, percent) {
  const share = Number(percent);
  if (share >= 100) return true;
  if (share <= 0) return false;
  let hash = 0;
  for (const char of String(deviceId || "device")) hash = (hash + char.charCodeAt(0) * 17) % 100;
  return hash < share;
}

module.exports = {
  round,
  levelFor,
  LEVEL_RANK,
  nextLevel,
  estimateMinutes,
  quoteDelivery,
  distanceMilesForAddress,
  areaFromAddress,
  haversineMiles,
  near,
  canSeeOpenRequest,
  shiftLeadHours,
  cashOutFee,
  levelBonus,
  mentorBonus,
  deviceProblem,
  reviewQuality,
  isMonthlyReviewDay,
  standing,
  earningsSplit,
  versionBelow,
  inRollout,
  previousLevel,
};
