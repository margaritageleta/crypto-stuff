
from Crypto.PublicKey.RSA import importKey, construct
import math
import sympy as sp
from Crypto.Util import number
from subprocess import run

binary = lambda n: bin(n)[2:]

if __name__ == "__main__":

    DIR = 'RSA_pseudo-20201123'
    FILENAME = 'margarita.geleta_pubkeyRSA_pseudo.pem'

    with open(f'{FILENAME}', 'r') as f:
        key = importKey(f.read())
        e = key.e
        n = key.n
        
    # Pasar n a binario y partir en 4 partes
    N = str(binary(n))
    chunk = len(N) // 4
    part = [N[i:i+chunk] for i in range(0, len(N), chunk)]

    # Definir m bits 
    m = len(part[0])

    # Definir las 3 partes en decimal
    A = int(part[0], 2)
    B = int(part[-1], 2)
    C = int(part[1] + part[2], 2)

    def crack_it(m, A, B, C):
        rs_prd = (A << m) + B 
        i_rs_prd = (B << m) + A
        rsq_ssq = C - i_rs_prd
        rs_sum_sq = rsq_ssq + 2 * rs_prd

        # Resolver sistema 
        r, s = sp.symbols('r s')
        sol = sp.solve([(r + s) ** 2 - rs_sum_sq, r * s - rs_prd], set = True)
        
        if len(sol[1]) == 0:
            # Añadir carry
            A = A - 1
            C = C + (1 << (m * 2))
            return crack_it(m, A, B, C)


        print(len(sol[1]))
        for solution in sol[1]:
            r, s = solution
            if r < 0 or s < 0 : continue
            if r > 0 and s > 0 : break

        p = int(binary(r) + binary(s), 2)
        q = int(binary(s) + binary(r), 2)
        if n == p * q:
            print('CRACKED')
            return p, q
        else:
            A = A - 1
            C = C + (1 << (m * 2))
            return crack_it(m, A, B, C)

    p, q = crack_it(m, A, B, C)

    assert(n == p * q)

    print(n)
    print()
    print(p * q)

    d = number.inverse(e, (p - 1) * (q - 1))
    private_key = construct((n, e, d))

    KEY_FILENAME = 'mi_clave_privada_RSA_pseudo.pem'

    with open(KEY_FILENAME, 'wb') as f:
        f.write(private_key.exportKey('PEM'))
        print('RSA private key generated.')

    # Decrypt RSA
    DEC_FILENAME = 'dec_RSA_pseudo.key'
    ENC_FILENAME = 'margarita.geleta_RSA_pseudo.enc'

    # openssl rsautl -decrypt -inkey mi_clave_privada_RSA.pem -in margarita.geleta_RSA_RW.enc -out dec_RSA.key
    run(['openssl', 'rsautl', '-decrypt', 
    '-inkey', KEY_FILENAME,
     '-in', ENC_FILENAME, 
     '-out', DEC_FILENAME])
    print('AES key decrypted with RSA private key.')

    with open(DEC_FILENAME, 'r') as f:
        key = f.read()
    
    # Decrypt AES
    ENC_AES_FILENAME = 'margarita.geleta_AES_pseudo.enc'
    OUTPUT_FILENAME = 'dec_AES_pseudo.png'

    # default openssl in Mac OS has no option -pbkdf2
    # /usr/local/Cellar/openssl@1.1/1.1.1h/bin/openssl enc -d -aes-128-cbc -pbkdf2 -in margarita.geleta_AES_RW.enc -out dec_AES -pass file:dec_RSA.key
    run(['/usr/local/Cellar/openssl@1.1/1.1.1h/bin/openssl', 'enc', '-d', '-aes-128-cbc', '-pbkdf2',
     '-in', ENC_AES_FILENAME, 
     '-out', OUTPUT_FILENAME,
     '-pass', f'file:{DEC_FILENAME}'])
    print('File decrypted with AES key.')


