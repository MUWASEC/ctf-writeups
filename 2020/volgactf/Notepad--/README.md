## Description
Notepad-- is the app to store your most private notes, with an extremely lightweight UI. Check it out!

[notepad](https://q.2020.volgactf.ru/files/1c9c1960b73808b8560c86ac81888c3c/notepad)

`nc notepad.q.2020.volgactf.ru 45678`

## Solution
```
1.) fill up tcache bin to leak libc from unsorted bin  
2.) tcache poisoning with uaf
3.) overwrite __free_hook with system to get a shell
```