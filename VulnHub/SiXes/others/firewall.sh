#!/bin/bash
# Author: ZOUAHI Hafidh (0x000c0ded)
# A simple home made firewall to block the usage of
#  automated tools during CTFs, such as SQLmap,
#  Dirbuster, and other bruteforcing tools.

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"

this_ip="$(ifconfig enp0s3 | awk '/inet / {print $2}' | tr -d '\n')"
path="/root/firewall/logs"
log_file="/root/firewall/firewall.log"
banned_ips=""
last_unban="$(date +%s)"
unban_interval=60
n_req=15
n_sec=3
rm -f $log_file
rm -r $path
mkdir $path
> /var/log/apache2/access.log
tail -f /var/log/apache2/access.log | while read line; do
  # Check if 60 seconds have passed since the last unban
  curr_time="$(date +%s)"
  if [[ "$((curr_time - last_unban))" -ge "$unban_interval" ]]; then
    iptables -F INPUT
    [ -z "$banned_ips" ] || echo "~-> $(date '+%Y:%m:%d %H:%M:%S'): Unbanning $banned_ips" >> $log_file
    banned_ips=""
    last_unban="$curr_time"
  fi
  ip_addr=$(echo "$line" | cut -d ' ' -f1)
  timestamp=$(date --date="$(echo "$line" | tr ' ' ':' | cut -d ':' -f5-7)" +%s)
  if [[ ! "$banned_ips" =~ "$ip_addr" ]] && test -f "$path/$ip_addr"; then
    req_num=$(cat "$path/$ip_addr" | cut -d ' ' -f1)
    req_num=$((req_num + 1))
    old_timestamp=$(cat "$path/$ip_addr" | cut -d ' ' -f2)
    # Check if at least $n_req requests were made within $n_sec seconds
    if [ "$ip_addr" != "$this_ip" ] && [[ "$((timestamp - old_timestamp))" -le $n_sec ]] && [[ $req_num -ge $n_req ]]; then
      # Ban this IP if it's not our IP
      iptables -A INPUT -s "$ip_addr" -p tcp --dport 80 -j DROP
      echo "~-> $(date '+%Y:%m:%d %H:%M:%S'): Banned $ip_addr for up to 60 seconds." >> $log_file
      banned_ips="${banned_ips}$ip_addr "
      rm "$path/$ip_addr"
    elif [[ "$((timestamp - old_timestamp))" -gt $n_sec ]] && [[ $req_num -lt $n_req ]]; then
      # Reset counters
      echo -n "1 $timestamp" > "$path/$ip_addr"
    else
      # Update counters
      echo -n "$req_num $old_timestamp" > "$path/$ip_addr"
    fi
  else
    # Create the file for the first time
    echo -n "1 $timestamp" > "$path/$ip_addr"
  fi
done