#!/bin/sh
exec socat TCP-LISTEN:1337,fork,reuseaddr EXEC:'stdbuf -o0 /home/challenge/espr'
