FROM ubuntu:20.04

RUN apt-get update && \
    apt-get -y install xinetd 

RUN useradd -d /home/ctf/ -m -p ctf -s /bin/bash ctf
RUN echo "ctf:ctf" | chpasswd

WORKDIR /home/ctf

COPY mmap1_updated .
COPY mmap1 /etc/xinetd.d/
RUN echo 'X-MAS{70_m4p_0r_70_unm4p_7h15_15_7h3_qu35710n}' > /home/ctf/flag.txt

EXPOSE 2003

CMD xinetd -dontfork