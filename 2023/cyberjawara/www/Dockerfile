FROM ubuntu:latest

RUN apt-get update -y && apt-get upgrade -y && apt-get install gcc -y
RUN apt-get install socat -y

RUN useradd --create-home --shell /bin/bash ctf
COPY www /home/ctf/
WORKDIR /home/ctf

RUN chmod 555 www

CMD socat TCP-LISTEN:3005,reuseaddr,fork EXEC:"./www",su=ctf && fg
