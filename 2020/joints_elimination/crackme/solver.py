import z3
#745UI-82JFS-9KNDB-CBJO7-OUM4G
s = z3.Solver()

len_flag = 25
a1 = [z3.Int("flag{}".format(i)) for i in range(len_flag) ]

# constraint printable
# for c in flag:
#     s.add(
#         z3.And(
#             ord(' ') <= c,
#             ord(' ') >= c))

s.add(a1[20] - a1[0] == 24 )
s.add( a1[8] + a1[5] == 126 )
s.add ( a1[14] * a1[5] == 3696 )
s.add ( a1[21] - a1[1] == 33 )
s.add ( a1[10] - a1[0] == 2 )
s.add ( a1[17] - a1[0] == 19 )
s.add ( a1[17] * a1[1] == 3848 )
s.add ( a1[4] + a1[6] == 123 )
s.add ( a1[13] * a1[16] == 4488 )
s.add ( a1[1] * a1[6] == 2600 )
s.add ( a1[13] * a1[23] == 3536 )
s.add ( a1[8] - a1[5] == 14 )
s.add ( a1[15] + a1[5] == 123 )
s.add ( a1[20] - a1[17] == 5 )
s.add ( a1[17] + a1[16] == 140 )
s.add ( a1[16] + a1[14] == 132 )
s.add ( a1[3] * a1[6] == 4250 )
s.add ( a1[18] + a1[14] == 145 )
s.add ( 2 * a1[13] == 136 )
s.add ( a1[17] - a1[10] == 17 )
s.add ( a1[11] + a1[8] == 145 )
s.add ( a1[9] + a1[1] == 135 )
s.add ( a1[11] + a1[24] == 146 )
s.add ( a1[3] - a1[7] == 11 )
s.add ( a1[0] - a1[2] == 2 )
s.add ( a1[11] - a1[13] == 7 )
s.add ( a1[3] + a1[4] == 158 )
s.add ( a1[3] - a1[16] == 19 )
s.add ( a1[4] - a1[14] == 7 )
s.add ( a1[12] * a1[1] == 4056 )
s.add ( a1[20] + a1[8] == 149 )
s.add ( a1[9] - a1[4] == 10 )
s.add ( a1[9] - a1[6] == 33 )
s.add ( a1[9] * a1[13] == 5644 )
s.add ( a1[16] + a1[5] == 122 )
s.add ( a1[16] - a1[10] == 9 )
s.add ( a1[17] + a1[24] == 145 )
s.add ( a1[20] - a1[13] == 11 )
s.add ( a1[18] * a1[11] == 5925 )
s.add ( a1[21] * a1[23] == 4420 )
s.add ( a1[22] * a1[7] == 5698 )
s.add ( a1[15] - a1[19] == 12 )
s.add ( a1[16] - a1[1] == 14 )
s.add ( a1[3] - a1[13] == 17 )
s.add ( a1[12] * a1[8] == 5460 )
s.add ( a1[21] * a1[13] == 5780 )
s.add ( a1[7] * a1[1] == 3848 )
s.add ( a1[22] + a1[6] == 127 )
s.add ( a1[13] + a1[5] == 124 )
s.add(a1[24] + a1[1] == 123)


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