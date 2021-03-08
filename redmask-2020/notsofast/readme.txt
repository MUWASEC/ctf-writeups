Can you pop up shell real quick?

nc 202.148.27.84 20001

Author: circleous

# problem & solution

arbitrary free and uaf from how2heap.patch
- ArrayBufferDetach -> js_free_rt(rt, ptr);

step by step exploitasi :
- alokasi buffer dengan size lebih besar dari size tcache/fastbin menggunakan ArrayBuffer(size). buffer ini digunakan untuk me-leak 
  address main_arena
- sebelum di-free buffer tersebut kita spray dengan value, terserah value apa. ini biar buffernya pas di-free
  glibc/allocator malloc bakal nganggep kalo itu chunk valid yg bisa dipakai ulang/recycle. chunk yg biasa dipakai ulang
  biasanya bakal dihandle unsorted_bin dan chunk yg masuk ke unsorted_bin bakal ditandai dengan address main_arena pada pointer &fd/&bk
- free dengan ArrayBufferDetach
- karna value disana dynamic, maka brute force index buffer tadi agar dapet address libc/main_arena yg cocok
- calculate offset then do simple tcache poisoning
- do __free_hook -> system
- win

- referensi exploitasi
https://dmxcsnsbh.github.io/2020/07/20/0CTF-TCTF-2020-Chromium-series-challenge/