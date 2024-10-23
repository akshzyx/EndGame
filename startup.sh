#!/bin/bash

ulimit -n 65536
ulimit -c unlimited
export LD_LIBRARY_PATH=/usr/local/lib
tor
#tor -f /etc/tor/torrc2
#tor -f /etc/tor/torrc3
#nohup socat UNIX-LISTEN:/run/tor_pass1.sock,fork,reuseaddr,unlink-early,user=www-data,group=www-data,mode=777 SOCKS4A:localhost:HOSTNAME1:80,socksport=9060 &
#nohup socat UNIX-LISTEN:/run/tor_pass2.sock,fork,reuseaddr,unlink-early,user=www-data,group=www-data,mode=777 SOCKS4A:localhost:HOSTNAME2:80,socksport=9070 &
exit 0
