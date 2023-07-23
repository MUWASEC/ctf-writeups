FROM ubuntu:latest
RUN apt-get update && \
    apt-get install -y lib32z1 xinetd --no-install-recommends && \
    apt-get install qemu-system socat -y && \
    rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash ctf

COPY build/bzImage /home/ctf
COPY build/initramfs.cpio.gz /home/ctf
COPY build/launch.sh /home/ctf/run
RUN chmod +x /home/ctf/run
WORKDIR /home/ctf

CMD socat TCP-LISTEN:3003,reuseaddr,fork EXEC:"./run"