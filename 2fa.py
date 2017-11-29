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

import json,sys,argparse

parser = argparse.ArgumentParser()
parser.add_argument("-j", "--json", help="The 2fa json file", default="./2fa.json")
parser.add_argument("-m", "--match", help="Only match entries that contain the provided string", default="")
parser.add_argument("-w", "--wait", help="Wait until the OTP expires and show count-down", action="store_true")
args = parser.parse_args()

try:
    myfile = open(args.json, 'rb')
except IOError:
    print("Failed to open the json file")
    sys.exit(1)

data = json.loads( myfile.read() )
accounts = data['Accounts']

myfile.close()

expires_at = int(time.time()+30)//30*30
for item in accounts:
    if not args.match or args.match.lower() in item['Name'].lower(): 
        print("%+12s -- %06d" % (item['Name'], otp(item['Secret'])))

print()

# Calc remaining
remaining_seconds = (expires_at - time.time())

if args.wait:
    for remaining in range(int(remaining_seconds), -1, -1):
        print("\r   remaining -- %-02d" % (remaining), end='')
        time.sleep(1)

    print()
else:
    m, s = divmod(expires_at, 60)
    h, m = divmod(m, 60)
    print ("Expires at: %d:%02d:%02d (in %d seconds)" % (h%24,m,s,remaining_seconds))
