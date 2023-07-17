**Author: Ingeborg**

**Difficulty: challenging**

**Category: pwn**

---

We've been hunting the space goblins for quite some time now. However, we're still having some trouble identifying their leader. In our last mission, we found a mysterious-looking chest that we think might contain some useful information. Could you help us open it?

```console
nc bufferfly.tghack.no 6002
```

or use a mirror closer to you:

* `nc us.bufferfly.tghack.no 6002` (US)
* `nc asia.bufferfly.tghack.no 6002` (Japan)

* [download binary](https://storage.googleapis.com/tghack-public/2020/9bcc0b2e67a6e54cf1e40ecbcbfe471e/bufferfly)
* [download source](https://storage.googleapis.com/tghack-public/2020/9bcc0b2e67a6e54cf1e40ecbcbfe471e/bufferfly.c)

#### Hints
- It might be a good idea to read up on [buffer overflows](https://19.tghack.no/page/Pwntions%20tutorial)
- Mprotect is a very useful function that can be used to make areas of memory executable.