# desc
UTCTF Sandbox 1000

New sandboxing solution just dropped

Run with: ./loader hello

By ggu
nc puffer.utctf.live 7132 

# solution
based on unicorn engine emulation on https://github.com/K-atc/uc-loader/blob/master/loader.cpp
arbitrary syscall by overwrite &exit_syscalls