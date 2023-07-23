FROM ubuntu:20.04

RUN apt-get update -y && apt-get -y upgrade
RUN apt-get install -y socat

RUN useradd -m -s /bin/bash ctf
COPY printfail /home/ctf/

EXPOSE 1337

CMD socat -T 30 \
    TCP-LISTEN:1337,nodelay,reuseaddr,fork \
    EXEC:"stdbuf -i0 -o0 -e0 /home/ctf/printfail"