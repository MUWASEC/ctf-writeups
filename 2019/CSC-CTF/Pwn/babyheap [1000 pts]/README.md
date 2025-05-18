Description:  
`nc babyheap.problem.cscctf.com 11113`

author: stürmisch

Hint:  
`smallbin consolidation`

Solution:  
`>` the bug is an `off-by-null` when inputting content in the `create()` function.  
`>` do **`Poison NULL byte`** or **`House of Einherjar`**  
&nbsp;&nbsp;&nbsp;&nbsp;`>` the bug will be useful to clear a `prev_inuse` bit in the victim chunk size field  
&nbsp;&nbsp;&nbsp;&nbsp;`>` this allows two unsorted bins to merge and overlap with a victim chunk located between them  
`>` leverage a double-free to perform tcache-poisoning, then overwrite `__free_hook`  