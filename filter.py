#!usr/bin/python
# -*- coding: utf-8 -*-

#coded by alem mexican friend
#edit by forky sexy friend

import socket
import sys

if len(sys.argv) < 2:
    print 'filter.py <input> <output> <protocol> <bytes>'
    sys.exit()

s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.settimeout(0.05)

file1 = sys.argv[1]
file2 = sys.argv[2]
proto = sys.argv[3]
size = int(sys.argv[4])

syntax = "[ip][space][bytes]"

with open(file1) as f:
    list = f.read().splitlines()

newfile = open(file2, 'w')

if proto == 'ntp':
    port = 123
    payload = '\x17\x00\x03\x2a\x00\x00\x00\x00'

elif proto == 'snmp':
    port = 161
    payload = '\x30\x20\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa5\x13\x02\x02\x00\x01\x02\x01\x00\x02\x01\x46\x30\x07\x30\x05\x06\x01\x28\x05\x00'

elif proto == 'cldap':
    port = 389
    payload = '\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x63\x6c\x61\x73\x73\x30\x00'
    
elif proto == 'ldap':
    port = 389
    payload = '\x30\x84\x00\x00\x00\x2d\x02\x01\x01\x63\x84\x00\x00\x00\x24\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x63\x6c\x61\x73\x73\x30\x84\x00\x00\x00\x00\x00'
    
elif proto == 'mdns':
    port = 5353
    payload = '\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09\x5F\x73\x65\x72\x76\x69\x63\x65\x73\x07\x5F\x64\x6E\x73\x2D\x73\x64\x04\x5F\x75\x64\x70\x05\x6C\x6F\x63\x61\x6C\x00\x00\x0C\x00\x01'    

elif proto == 'ard':
    port = 3283
    payload = '\x00\x14\x00\x00'

elif proto == 'wsd':
    port = 3702
    payload = '\x3c\x3a\x2f\x3e'

elif proto == 'dvr':
    port = 37810
    payload = '\x44\x48\x49\x50'
else:
    print 'invalid protocol'
    sys.exit()

c = 0
servers = []
while c < len(list):
    split = list[c].split(" ") 
    s.sendto(payload, (split[0], port))
    try:
        data, addr = s.recvfrom(65500)
        syntax_output = ""
        if len(data) >= size:
            if any(addr[0] in s for s in servers):
                rip = 0
            else:
                print 'reflector: %s response size: %i' % ( addr[0],len(data) )
                syntax_output = syntax.replace("[space]", " ", 5) # 5 is fine.
                syntax_output = syntax_output.replace("[bytes]", str(len(data)), 5) # 5 is fine.
                syntax_output = syntax_output.replace("[ip]", str(addr[0]), 5) # 5 is fine.
                newfile.write(str(syntax_output)+'\n')
                servers.append(addr[0])
    except Exception and socket.error and socket.timeout:
        I = 0
    c += 1

newfile.close()
with open(file2) as e:
    count = e.read().splitlines()
print 'file %s with %i reflectors' % ( file2,len(count) )
