# SNMP cracker

This tool is inspired from the work of 0x0ff : https://www.0x0ff.info/2013/snmpv3-authentification/ where he teaches us why intercepted packet of SNMP are vulnerable to brutfirce attacks. This is exactly what this tool do.

## Usage :

The argument whole message is the array of bytes in hexadecimal that you can find in the sniffed packet.

![Very cool picture](https://www.0x0ff.info/wp-content/uploads/2013/04/Trace_1_packet.png)

Now, you are ready to crack the password :
```
$ python3 smnp_cracker.py --msg 30818002010330110204580b8cc7020300ffe30401050201030431302f041180001f888062dc7f4c15465c510000000002010302017c040475736572040c6fb833cba1dbe6415be03b3504003035041180001f888062dc7f4c15465c51000000000400a11e0204334304ff0201000201003010300e060a2b06010201041e0105010500 --dict ~/wordlists/rockyou.txt --hash md5 --t 10
╔═══╦═╗╔═╦═╗─╔╦═══╗───────────╔╗
║╔═╗║║╚╝║║║╚╗║║╔═╗║───────────║║
║╚══╣╔╗╔╗║╔╗╚╝║╚═╝║╔══╦═╦══╦══╣║╔╦══╦═╗
╚══╗║║║║║║║╚╗║║╔══╝║╔═╣╔╣╔╗║╔═╣╚╝╣║═╣╔╝
║╚═╝║║║║║║║─║║║║───║╚═╣║║╔╗║╚═╣╔╗╣║═╣║
╚═══╩╝╚╝╚╩╝─╚═╩╝───╚══╩╝╚╝╚╩══╩╝╚╩══╩╝
[+] Selected hash function : md5
[+] msgAuthoritativeEngineID : 80001f888062dc7f4c15465c5100000000
[+] msgAuthenticationParameters : 6fb833cba1dbe6415be03b35
Tested : 11267/14344392
Password found : p@ssw0rd
```

Number of thread is 10 by default.

Hash is md5 by default.

## Todo

Add support of sha-1. The length of the signature will be different 
