import pickle
from time import time
import hashlib
from random import randint
from Crypto.Util import number
from Crypto import Random

D = 16

class rsa_key:
    def __init__(self, bits_modulo = 2048, e = 2 ** 16 + 1):
        '''
        genera la clau publica RSA asociada a la clau RSA "rsa_key"
        '''
        self.publicExponent = e
        self.primeP = number.getPrime(bits_modulo, randfunc = Random.get_random_bytes)
        self.primeQ = number.getPrime(bits_modulo, randfunc = Random.get_random_bytes)

        self.modulus = self.primeP * self.primeQ

        self.privateExponent = number.inverse(self.publicExponent, (self.primeP - 1) * (self.primeQ - 1))
        
        self.privateExponentModulusPhiP = number.inverse(self.privateExponent, self.primeP - 1)
        self.privateExponentModulusPhiQ = number.inverse(self.privateExponent, self.primeQ - 1)
        self.inverseQModulusP = number.inverse(self.primeQ, self.primeP)

    def sign(self, message):
        '''
        retorma un enter que es la signatura de "message" 
        feta amb la clau RSA fent servir el TXR
        Teorema Xines
        '''
        d1 = self.privateExponent % (self.primeP - 1)
        d2 = self.privateExponent % (self.primeQ - 1)

        p1 = number.inverse(self.primeP, self.primeQ)
        q1 = number.inverse(self.primeQ, self.primeP)

        c1 = pow(message, d1, self.primeP)
        c2 = pow(message, d2, self.primeQ)

        return (c1 * q1 * self.primeQ + c2 * p1 * self.primeP) % self.modulus

    def sign_slow(self, message):
        '''
        retorma un enter que es la signatura de "message" 
        feta amb la clau RSA sense fer servir el TXR
        '''
        return pow(message, self.privateExponent, self.modulus)

class rsa_public_key:
    def __init__(self, rsa_key):
        '''
        genera la clau publica RSA asociada a la clau RSA "rsa_key"
        '''
        self.publicExponent = rsa_key.publicExponent
        self.modulus = rsa_key.modulus

    def verify(self, message, signature):
        '''
        retorna el boolea True si "signature" es correspon amb una
        signatura de "message" feta amb la clau RSA associada a la clau
        publica RSA.
        En qualsevol altre cas retorma el boolea False
        '''
        return message == pow(signature, self.publicExponent, self.modulus)

class transaction:
    def __init__(self, message, RSAkey):
        '''
        genera una transaccio signant "message" amb la clau "RSAkey"
        '''
        self.public_key = rsa_public_key(RSAkey)
        self.message = message
        self.signature = RSAkey.sign(message)

    def verify(self):
        '''
        retorna el boolea True si "signature" es correspon amb una
        signatura de "message" feta amb la clau publica "public_key".
        En qualsevol altre cas retorma el boolea False
        '''
        return self.public_key.verify(self.message, self.signature)

class block:
    def __init__(self):
        '''
        crea un bloc (no necesariamnet valid)
        '''
        self.block_hash = None
        self.previous_block_hash = None
        self.transaction = None
        self.seed = None
    
    def generate_block_hash(self):
        while True:  # For setting a correct seed
            self.seed = randint(0, 2 ** 256)
            entrada = str(self.previous_block_hash)
            entrada += str(self.transaction.public_key.publicExponent)
            entrada += str(self.transaction.public_key.modulus)
            entrada += str(self.transaction.message)
            entrada += str(self.transaction.signature)
            entrada += str(self.seed)
            entrada = int(hashlib.sha256(entrada.encode()).hexdigest(), 16)
            if entrada < 2 ** (256 - D):
                break
        self.block_hash = entrada

    def generate_wrong_block_hash(self):
        while True:
            block.seed = randint(0, 2 ** 256)
            entrada = str(self.previous_block_hash)
            entrada += str(self.transaction.public_key.publicExponent)
            entrada += str(self.transaction.public_key.modulus)
            entrada += str(self.transaction.message)
            entrada += str(self.transaction.signature)
            entrada += str(self.seed)
            entrada = int(hashlib.sha256(entrada.encode()).hexdigest(), 16)
            if entrada > 2 ** (256 - D):
                break
        self.block_hash = entrada
    
    def genesis(self, transaction):
        '''
        genera el primer bloc d'una cadena amb la transaccio "transaction" 
        que es caracteritza per:
        - previous_block_hash=0
        - ser valid
        '''
        self.previous_block_hash = 0
        self.transaction = transaction
        self.generate_block_hash()

        return self
    
    def next_block(self, transaction):
        '''
        genera el seguent block valid amb la transaccio "transaction"
        '''
        new_block = block()
        new_block.transaction = transaction
        new_block.previous_block_hash = self.block_hash
        new_block.generate_block_hash()
        return new_block

    def verify_block(self):
        '''
        Verifica si un bloc es valid:
        -Comprova que el hash del bloc anterior cumpleix las condicions exigides
        -Comprova la transaccio del bloc es valida
        -Comprova que el hash del bloc cumpleix las condicions exigides
        Si totes les comprovacions son correctes retorna el boolea True.
        En qualsevol altre cas retorma el boolea False
        '''
        proof_of_work = 2 ** (256 - D)
        hashes = self.previous_block_hash < proof_of_work and self.block_hash < proof_of_work

        return hashes and self.transaction.verify()

class block_chain:
    def __init__(self, transaction):
        '''
        genera una cadena de blocs que es una llista de blocs,
        el primer bloc es un bloc "genesis" generat amb la transaccio "transaction"
        '''
        first_block = block().genesis(transaction)
        self.list_of_blocks = [first_block]

    def add_block(self, transaction):
        '''
        afegeix a la llista de blocs un nou bloc valid generat amb la transaccio "transaction"
        '''
        new_block = self.list_of_blocks[-1].next_block(transaction)
        self.list_of_blocks.append(new_block)

    def add_wrong_block(self, transaction):
        last_block = self.list_of_blocks[-1]
        new_block = block()

        new_block.transaction = transaction
        new_block.previous_block_hash = last_block.block_hash

        new_block.generate_wrong_block_hash()

        self.list_of_blocks.append(new_block)

    def verify(self):
        '''
        verifica si la cadena de blocs es valida:
        - Comprova que tots el blocs son valids
        - Comprova que el primer bloc es un bloc "genesis"
        - Comprova que per cada bloc de la cadena el seguent es el correcte
        Si totes les comprovacions son correctes retorna el boolea True.
        En qualsevol altre cas retorma el boolea False i fins a quin bloc la cadena es valida
        '''
        for block in self.list_of_blocks:
            if not block.verify_block(): return False
        return True