import z3
s = z3.Solver()

len_flag = 0x14
a1 = [z3.Int("{}".format(i)) for i in range(len_flag)]

# sym.check1
# ----------
# if ((((iVar1 == 0x14) && (s[4] == '_')) && (uVar2 = sym.imp.strlen(s), s[(uVar2 >> 1) - 1] == '_')) &&
#    (s[0xe] == '_')) {
#     return 1;
# }
# return 0;
s.add(a1[4] == ord('_'))
s.add(a1[(len_flag>>1) - 1] == ord('_')) # 0x9
s.add(a1[0xe] == ord('_'))



# sym.check3
# ----------
# bool sym.check3(char *arg_8h, int32_t arg_ch, int32_t arg_10h)
# {
#     sym.__x86.get_pc_thunk.ax();
#     return arg_8h[arg_10h] == *(char *)(arg_ch + arg_10h);
# }
#
# 
for i in range(len_flag):
    if i == 0x4 or i == 0x9 or i == 0xe: continue

    # sym.check3(s_00, "H4MA", 0)
    elif i == 0: s.add(a1[i] == ord('H'))
    elif i == 1: s.add(a1[i] == ord('4'))
    elif i == 2: s.add(a1[i] == ord('M'))
    elif i == 3: s.add(a1[i] == ord('A'))

    # sym.check3(s_00 + 5, "H4MA", 1)
    elif i == 0+5: s.add(a1[i] == ord('H'))
    elif i == 1+5: s.add(a1[i] == ord('4'))
    elif i == 2+5: s.add(a1[i] == ord('M'))
    elif i == 3+5: s.add(a1[i] == ord('A'))

    # sym.check3(s_00 + (uVar2 >> 1), "H4MA", 2)
    elif i == 0+(len_flag>>1): s.add(a1[i] == ord('H'))
    elif i == 1+(len_flag>>1): s.add(a1[i] == ord('4'))
    elif i == 2+(len_flag>>1): s.add(a1[i] == ord('M'))
    elif i == 3+(len_flag>>1): s.add(a1[i] < 0x7f) # prevent unicode char

    # sym.check3(s_00 + 0xf, "H4MA", 3)
    elif i == 0+0xf: s.add(a1[i] == ord('H'))
    elif i == 1+0xf: s.add(a1[i] == ord('4'))
    elif i == 2+0xf: s.add(a1[i] == ord('M'))
    elif i == 3+0xf: s.add(a1[i] == ord('A'))
    else: 
        s.add(a1[i] < 0x7f) # prevent unicode char



# sym.check2
# ----------
# var_10h = 0;
# var_ch = 0;
# while( true ) {
#     uVar1 = sym.imp.strlen(s);
#     if (uVar1 <= (uint32_t)var_10h) break;
#     var_ch = var_ch + (int32_t)s[var_10h];
#     var_10h = var_10h + 1;
# }
# return var_ch == 0x5f4;
s.add(
    a1[0x0] + a1[0x1]  + a1[0x2]  + a1[0x3]  +
    a1[0x4] + a1[0x5]  + a1[0x6]  + a1[0x7]  + a1[0x8]  + a1[0x9] +
    a1[0xa] + a1[0xb]  + a1[0xc]  + a1[0xd]  + a1[0xe]  +
    a1[0xf] + a1[0x10] + a1[0x11] + a1[0x12] + a1[0x13] == 0x5f4)



r = s.check()
if r == z3.sat:
    print("[+] SUCCESS: solution found")
    m = s.model()
    print(m)
    fs = ""
    for c in a1:
        fs += chr(m[c].as_long())
    print(fs)

else:
    print("[-] ERROR: solution not found")
    exit(0)
# Securinets{k3yg3n_r0ck5!!}