# Marcus Botacin
# Encode a binary payload in base64 and XOR it

import sys
import base64

# encode/decode data with a XOR key
def XOR(data):
    KEY = 0x35 # single-byte key, but it might be changed
    for i,b in enumerate(data):
        data[i] = data[i] ^ KEY # I'm doing it byte-to-byte to check, but one could do all at once
    return data

def string_to_binary(s):
    return ''.join(map('{:08b}'.format, bytearray(s, encoding='utf-8')))

# Read the binary
data = open(sys.argv[1],'rb').read()
# Encode using base64
bdata = base64.b64encode(data)
# XOR the encoded data
xdata = XOR(bytearray(bdata))
xdata = string_to_binary(xdata)
# store in a new file
open("test.bin","wb").write(xdata)