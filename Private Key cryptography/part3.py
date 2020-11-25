# LAB 2 ~ PART 3 ~ MARGARITA GELETA

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import hashlib
import subprocess
import os

id = '2020_09_25_10_31_34_roser.cantenys'
filename = f'{id}.enc'
file_backdoor = f'{id}.puerta_trasera.enc'
filekey = f'{id}.key'
output = f'{id}.jpeg'
output_backdoor = f'{id}.puerta_trasera.dec'

BLOCK_SIZE = 16
ASCII = ''.join([chr(i) for i in range(256)])

def K_i(): 
    for a in ASCII: 
        for b in ASCII: 
            yield f'{a * 8}{b * 8}'

if __name__ == "__main__":

    """ PART 1 =========================== """

    with open(filename, 'rb') as f:
        C = f.read()
        IV = C[:BLOCK_SIZE]

    with open(filekey, 'rb') as f:
        K = f.read()

    aes = AES.new(K, AES.MODE_CBC, IV)

    M = unpad(aes.decrypt(C[BLOCK_SIZE:]), BLOCK_SIZE, style = 'pkcs7')
    #M = aes.decrypt(C[BLOCK_SIZE:])
    print(M[0:250]) 
    """
    Amb el print he pogut veure aixo:
    b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\
    x00\xff\xfe\x00;CREATOR: gd-jpeg v1.0 (using IJG JPEG v62), 
    quality = 85\n\
    I m'ha semblat molt sospitosa la paraula JPEG.
    He utilitzat la comanda file a la consola per veure
    el tipus del fitxer desxifrat. I era un JPEG.
    Per aixo he guardat el output com a JPEG.
    """
    with open(output, 'wb') as f:
        f.write(M)
    
    """ PART 2 =========================== """
    with open(file_backdoor, 'rb') as f:
        C = f.read()
        K_i = K_i()
        BLOCK_SIZE = 16
        # print(list(K_i))

        it = 0

        while True:
            try:
                preMasterKey = next(K_i).encode()
                H = hashlib.sha256(preMasterKey).digest()
                K = H[:BLOCK_SIZE]
                IV = H[BLOCK_SIZE:]
                aes = AES.new(K, AES.MODE_CBC, IV)
                M = unpad(aes.decrypt(C), BLOCK_SIZE, style = 'pkcs7')

                with open(output_backdoor, 'wb') as f:
                    f.write(M)

                decoded_filetype = os.popen(f'file {output_backdoor}').read()
                if(decoded_filetype.find('data') == -1): 
                    print(decoded_filetype)
                    print(M[0:250])
                    print(f'K: {K}, it: {it}')
                if it == 99: 
                    break
                it += 1
            except ValueError:
                pass
            except StopIteration:
                break
            




    