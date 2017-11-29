#!/usr/bin/env python3
import hmac, base64, struct, hashlib, time

def otp(secret):
    # Timer-based OTP
    secret = secret.replace(" ", "")
    secret += '=' * (-len(secret) % 8)  # Add correct '=' padding

    intervals_no = int(time.time())//30 

    # Counter-based OTP
    key = base64.b32decode(secret, True)
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 15
    h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000

    return h

import json,sys

try:
    myfile = open('./2fa.json', 'rb')
except IOError:
    print("Failed to open the json file")
    sys.exit(1)

data = json.loads( myfile.read() )
accounts = data['Accounts']

myfile.close()

runat = int(time.time()+30)//30*30
for item in accounts:
    print("%+12s -- %06d" % (item['Name'], otp(item['Secret'])))

print("             __ ______")

# Calc remaining
remaining_seconds = (runat - time.time())

for remaining in range(int(remaining_seconds), -1, -1):
    print("\r   remaining -- %-02d" % (remaining), end='')
    time.sleep(1)

print("\n")
