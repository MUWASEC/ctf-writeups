Description:  
`nc babyheap.problem.cscctf.com 11113`

author: stürmisch

Hint:  
`smallbin consolidation`

Solution:  
`>` the bug is an `off-by-null` when inputting content in the `create()` function.  
`>` do **`Poison NULL byte`** or **`House of Einherjar`**  
    `>` this will clear `prev_inuse` flag and merged with active chunk  
`>` leverage a double-free to perform tcache-poisoning, then overwrite `__free_hook`  