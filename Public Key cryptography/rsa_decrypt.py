
# openssl rsa -outform der -in margarita.geleta_pubkeyRSA_RW.pem -pubin -text -modulus

from math import gcd
from Crypto.PublicKey.RSA import importKey, construct
from factordb.factordb import FactorDB
from Crypto.Util import number
import math
from glob import glob
from subprocess import run

if __name__ == "__main__":

    DIR = 'RSA_RW-20201123'
    FILENAME = 'margarita.geleta_pubkeyRSA_RW.pem'

    with open(f'{FILENAME}', 'r') as f:
        key = importKey(f.read())
        # print(f'Exponent: {key.e}')
        # print(f'Modulus: {key.n}')

        e = key.e
        n = key.n
    
    # Find p & q (https://eprint.iacr.org/2012/064.pdf)
    for filename in glob(f'{DIR}/*pubkeyRSA_RW*.pem'):
        f = open(filename)
        key = importKey(f.read())
        gcd_key = gcd(n, key.n)
        if gcd_key != 1 and filename != f'{DIR}/{FILENAME}':
            print(f'Found match with {f.name}.')
            if number.isPrime(gcd_key) and number.isPrime(n // gcd_key):
                p = gcd_key
                q = n // gcd_key
                assert(n == p * q)
                print('RSA cracked.')
                break
    
    d = number.inverse(e, (p - 1) * (q - 1))
    private_key = construct((n, e, d))

    KEY_FILENAME = 'mi_clave_privada_RSA.pem'

    with open(KEY_FILENAME, 'wb') as f:
        f.write(private_key.exportKey('PEM'))
        print('RSA private key generated.')

    # Decrypt RSA
    DEC_FILENAME = 'dec_RSA.key'
    ENC_FILENAME = 'margarita.geleta_RSA_RW.enc'

    # openssl rsautl -decrypt -inkey mi_clave_privada_RSA.pem -in margarita.geleta_RSA_RW.enc -out dec_RSA.key
    run(['openssl', 'rsautl', '-decrypt', 
    '-inkey', KEY_FILENAME,
     '-in', ENC_FILENAME, 
     '-out', DEC_FILENAME])
    print('AES key decrypted with RSA private key.')

    with open(DEC_FILENAME, 'r') as f:
        key = f.read()
    
    # Decrypt AES
    ENC_AES_FILENAME = 'margarita.geleta_AES_RW.enc'
    OUTPUT_FILENAME = 'dec_AES.png'

    # default openssl in Mac OS has no option -pbkdf2
    # /usr/local/Cellar/openssl@1.1/1.1.1h/bin/openssl enc -d -aes-128-cbc -pbkdf2 -in margarita.geleta_AES_RW.enc -out dec_AES -pass file:dec_RSA.key
    run(['/usr/local/Cellar/openssl@1.1/1.1.1h/bin/openssl', 'enc', '-d', '-aes-128-cbc', '-pbkdf2',
     '-in', ENC_AES_FILENAME, 
     '-out', OUTPUT_FILENAME,
     '-pass', f'file:{DEC_FILENAME}'])
    print('File decrypted with AES key.')

"""

Public-Key: (2047 bit)
Modulus:
    4d:a0:e8:3d:fd:0d:ca:de:c8:b4:89:bb:d4:d9:ed:
    e1:84:93:9d:b3:13:9b:65:ec:8d:98:4b:77:95:8b:
    d0:d6:6f:e2:56:8a:d2:7f:5b:42:a2:e1:ca:7f:5d:
    ca:23:1d:ee:5f:c6:f0:b0:a2:13:81:f3:ac:4c:b7:
    fb:3b:6a:08:68:d6:ce:6d:45:1a:e9:e2:23:99:9a:
    a2:0f:1d:ef:59:d1:76:83:d3:07:36:08:04:d3:ca:
    05:4a:37:45:0f:a1:52:ff:cb:b3:4f:34:1f:93:e6:
    c5:a8:f6:f9:98:d3:17:b7:6d:a9:30:c6:48:bc:5f:
    50:e4:df:c1:aa:cc:79:e4:fc:b6:24:e3:80:2d:40:
    57:06:a2:8a:35:57:96:a7:15:07:75:15:94:f0:2e:
    21:f1:51:f4:1d:89:aa:e5:ad:42:a7:ca:f1:32:a1:
    3a:34:be:98:47:a7:f0:30:47:10:e2:e0:18:b0:58:
    43:93:03:06:a1:5f:b3:5f:43:c3:cc:27:86:a7:6b:
    ad:8f:f2:5c:f5:e6:33:e4:3c:95:71:29:48:26:6c:
    94:1b:d5:83:ff:72:53:09:cb:fe:0e:87:f9:e3:5e:
    c3:7e:2b:f1:ab:dc:81:71:4e:99:da:0e:08:38:55:
    18:4a:36:54:e3:86:6d:55:22:29:5d:42:1e:bc:7d:
    9d
Exponent: 65537 (0x10001)
Modulus=4DA0E83DFD0DCADEC8B489BBD4D9EDE184939DB3139B65EC8D984B77958BD0D66FE2568AD27F5B42A2E1CA7F5DCA231DEE5FC6F0B0A21381F3AC4CB7FB3B6A0868D6CE6D451AE9E223999AA20F1DEF59D17683D307360804D3CA054A37450FA152FFCBB34F341F93E6C5A8F6F998D317B76DA930C648BC5F50E4DFC1AACC79E4FCB624E3802D405706A28A355796A71507751594F02E21F151F41D89AAE5AD42A7CAF132A13A34BE9847A7F0304710E2E018B05843930306A15FB35F43C3CC2786A76BAD8FF25CF5E633E43C95712948266C941BD583FF725309CBFE0E87F9E35EC37E2BF1ABDC81714E99DA0E083855184A3654E3866D5522295D421EBC7D9D

print(math.ceil(math.log2(modulus)))

"""

# https://loginroot.com/cracking-the-rsa-keys-part-1-getting-the-private-exponent/
    

    
