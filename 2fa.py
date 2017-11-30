#!/usr/bin/env python3
import hmac, base64, struct, hashlib, time

def totp(secret):
    secret = secret.replace(" ", "")
    secret += '=' * (-len(secret) % 8)  # Add correct '=' padding
    intervals_no = int(time.time())//30 
    key = base64.b32decode(secret, True)
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 15
    d = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    return d

import json,sys,argparse

parser = argparse.ArgumentParser()
parser.add_argument("-j", "--json", help="The 2fa json file", default="./my2fa.json")
parser.add_argument("-m", "--match", help="Only match entries that contain the provided string", default="")
parser.add_argument("-w", "--wait", help="Wait until the OTP expires and show count-down", action="store_true")
args = parser.parse_args()

try:
    myfile = open(args.json, 'rb')
    raw = myfile.read()
    myfile.close()
    data = json.loads( raw )
    for one in data['Accounts']: # Validate against the expected schema and format.
        if not isinstance(one['Name'],str) or not isinstance(one['Secret'],str) or not base64.b32decode(one['Secret']+'=' * (-len(one['Secret']) % 8),True):
            raise Exception("The json schema doesn't comply")
except Exception as err:
    print("Failed to process the json file:", err)
    sys.exit(1)

expires_at = int(time.time()+30)//30*30
for item in data['Accounts']:
    if not args.match or args.match.lower() in item['Name'].lower(): 
        print("%+12s -- %06d" % (item['Name'], totp(item['Secret'])))

print()

remaining_seconds = (expires_at - time.time())

if args.wait:
    for remaining in range(int(remaining_seconds), -1, -1):
        print("\r   remaining -- %-02d" % (remaining), end='')
        time.sleep(1)

    print()
else:
    t = time.localtime(expires_at)
    print("Expires at: %s - in %d seconds." %(time.strftime('%H:%M:%S', t), remaining_seconds))
