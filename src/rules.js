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
  for (const step of NEXT_LEVEL) {
    if (completed < step.at) {
      return { name: step.name, at: step.at, remaining: step.at - completed };
    }
  }
  return { name: "diamond", at: 500, remaining: 0 };
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

module.exports = {
  round,
  levelFor,
  LEVEL_RANK,
  nextLevel,
  quoteDelivery,
  distanceMilesForAddress,
  areaFromAddress,
  haversineMiles,
  near,
  canSeeOpenRequest,
  shiftLeadHours,
  cashOutFee,
};
