#!/bin/bash

handler()
{
echo "Hemm, nice one but i'm going out! "
kill -9 $$
}

trap handler  1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21
function check {
        if [[ $1 == *[0123456789abdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"\#\$\%\&\'\(\)\+\.\:\*\;\<\=\>\@\[\\\]\^\_\`\|]* ]]
        then 
                return 0
        fi
	if echo $1|grep -q " "
	then
		return 0
	fi

        return 1
}

echo "*-* Welcome to SECURINETS CTF! *-*"
echo "[+] Changing the current directory leaving the flag alone :D !"
cd sub
echo "[+] Starting the task"
while :
do
    read input
    if check "$input"
    then
        echo "We don't do this here..."
    else
        output="echo -n executing : $input"
        eval $input
    fi
done
