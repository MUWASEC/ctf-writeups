# Description
It is a terrible crime to slay a canary. Killing a canary will keep your exploit alive even if you are an inch from segfaults. But at a terrible price.

`nc 2020.redpwnc.tf 31744`  
**NOTE**: This and later pwn problems provide Dockerfiles

To run on localhost:1337 with the current directory mounted at `/ctf`,

```bash
tar xf dead-canary.tar.gz && echo fake_flag > bin/flag.txt && docker run -v ${PWD}:/ctf --cap-add=SYS_PTRACE --rm --name redpwnctf-dead-canary -itp 1337:9999 $(docker build -q .)
```

You can get a shell with,  

```bash
docker exec -it redpwnctf-dead-canary bash
```

We've also provided a simple install script to help setup an environment quickly.

```bash
apt-get update && apt-get install -qy curl && curl https://raw.githubusercontent.com/redpwn/dockerfiles/master/quick-install.sh | sh
```