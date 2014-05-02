#encoding:gbk

'''
    DNS Client to fetch zone transfer data
    Blog: http://www.lijiejie.com
    my[at]lijiejie.com
'''

import socket
import struct
import sys


LEN_QUERY = 0    # Length of Query String

def gen_query(domain):
    import random
    TRANS_ID = random.randint(1, 65535)       # random ID
    FLAGS = 0; QDCOUNT = 1; ANCOUNT = 0; NSCOUNT = 0; ARCOUNT = 0
    data = struct.pack(
        '!HHHHHH',
        TRANS_ID, FLAGS,QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
        )
    query = ''
    for label in domain.strip().split('.'):
        query += struct.pack('!B', len(label)) + label.lower()
    query += '\x00'    # end of domain name
    data += query
    global LEN_QUERY
    LEN_QUERY = len(query)    # length of query section
    q_type = 252    # Type AXFR = 252
    q_class = 1    # CLASS IN
    data += struct.pack('!HH', q_type, q_class)
    data = struct.pack('!H', len(data) ) + data    # first 2 bytes should be length
    return data


OFFSET = 0    # Response Data offset
TYPES = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA',
         12: 'PTR', 15: 'MX', 16: 'TXT',
         28: 'AAAA', 38: 'A6', 99: 'SPF',}
def decode(response):
    RCODE = struct.unpack('!H', response[2:4] )[0] & 0b00001111 # last 4 bits is RCODE
    if RCODE != 0:
        print 'Transfer Failed. %>_<%'
        sys.exit(-1)
    anwser_rrs = struct.unpack('!H', response[6:8] )[0]
    print '<< %d records in total >>' % anwser_rrs
    global LEN_QUERY, OFFSET
    OFFSET = 12 + LEN_QUERY + 4    # header = 12, type + class = 4
    while OFFSET < len(response):
        name_offset = response[OFFSET: OFFSET + 2]    # 2 bytes
        name_offset = struct.unpack('!H', name_offset)[0]
        if name_offset > 0b1100000000000000:
            name = get_name(response, name_offset - 0b1100000000000000, True)
        else:
            name = get_name(response, OFFSET)
        type = struct.unpack('!H', response[OFFSET: OFFSET+2] )[0]
        type = TYPES.get(type, '')
        if type != 'A': print name.ljust(20), type.ljust(10)
        OFFSET += 8    # type: 2 bytes, class: 2bytes, time to live: 4 bytes
        data_length = struct.unpack('!H', response[OFFSET: OFFSET+2] )[0]
        if data_length == 4 and type == 'A':
            ip = [str(num) for num in struct.unpack('!BBBB', response[OFFSET+2: OFFSET+6] ) ]
            print name.ljust(20), type.ljust(10), '.'.join(ip)
        OFFSET += 2 + data_length
     
# is_pointer: an name offset or not        
def get_name(response, name_offset, is_pointer=False):
    global OFFSET
    labels = []
    while True:
        num = struct.unpack('B', response[name_offset])[0]
        if num == 0 or num > 128: break    # end with 0b00000000 or 0b1???????
        labels.append( response[name_offset + 1: name_offset + 1 + num] )
        name_offset += 1 + num
        if not is_pointer: OFFSET += 1 + num
    name = '.'.join(labels)
    OFFSET += 2    # 0x00
    return name
    

if len(sys.argv) != 3:
    print 'Fetch DNS Zone Transfer records.\nUsage: \n    %s {DNS sever} domain' % sys.argv[0]
    sys.exit(0)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect( (sys.argv[1], 53) )
data = gen_query(sys.argv[2])
s.send(data)
s.settimeout(2.0)    # In case recv() blocked
response = s.recv(4096)
res_len = struct.unpack('!H', response[:2])[0]    # Response Content Length
while len(response) < res_len:
    response += s.recv(4096)
s.close()
decode(response[2:])
