# LAB 2 ~ PART 2 ~ MARGARITA GELETA
# Searched for AES-128-bit
# https://github.com/Joshua-Riek/AES-128bit/blob/master/aes.py
# AES implementation by Joshua Riek
# modified by Margarita Geleta

import binascii
import re
import warnings
import random
import matplotlib.pyplot as plt

# To ignore the warnings from AES implementation use
# python3 -W ignore part2.py

class AES(object):
    """ Started on 3/16/2017
    The Advanced Encryption Standard (AES), also known by its original
    name Rijndael, is a specification for the encryption of electronic
    data established by the U.S. National Institute of Standards and
    Technology (NIST) in 2001. AES is a subset of the Rijndael cipher
    developed by two Belgian cryptographers, Joan Daemen and Vincent
    Rijmen, who submitted a proposal to NIST during the AES selection
    process. Rijndael is a family of ciphers with different key
    and block sizes.

    # Instructions for my AES implication
    aes = AES(mode='ecb', input_type='hex')
            
    # Test vector 128-bit key
    key = '000102030405060708090a0b0c0d0e0f'
        
    # Encrypt data with your key
    cyphertext = aes.encryption('00112233445566778899aabbccddeeff', key)
        
    # Decrypt data with the same key
    plaintext = aes.decryption(cyphertext, key) 
    """
    def __init__(self, mode, input_type, 
                byteSubId = False, 
                shiftRowsId  = False,  
                mixColumnsId = False, 
                iv = None):
        self.mode = mode
        self.input = input_type
        self.byteSubId = byteSubId
        self.shiftRowsId = shiftRowsId
        self.mixColumnsId = mixColumnsId
        self.iv = iv
        self.Nb = 0
        self.Nk = 0
        self.Nr = 0

        # Rijndael S-box
        self.sbox = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
            0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
            0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
            0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
            0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
            0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
            0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
            0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
            0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
            0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
            0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
            0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
            0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
            0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
            0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
            0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
            0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
            0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
            0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
            0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
            0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
            0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
            0x54, 0xbb, 0x16]

        # Rijndael Inverted S-box
        self.rsbox = [
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
            0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
            0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54,
            0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
            0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
            0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8,
            0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
            0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
            0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab,
            0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
            0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1,
            0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
            0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
            0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
            0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d,
            0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0,
            0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
            0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60,
            0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
            0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5,
            0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b,
            0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55,
            0x21, 0x0c, 0x7d]

        self.rcon = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

    @staticmethod
    def pad(data, block=16):
        """ Padding method for data
        :param data: Data to pad
        :param int block: Block size
        :return: Padded data """
        if block < 2 or block > 255:
            raise ValueError("Block Size must be < 2 and > 255")

        if len(data) is block: return data
        pads = block - (len(data) % block)
        return data + binascii.unhexlify(('%02x' % int(pads)).encode()) + b'\x00' * (pads - 1)

    @staticmethod
    def unpad(data):
        """ Un-Padding for data
        :param data: Data to be un-padded
        :return: Data with removed padding """
        p = None
        for x in data[::-1]:
            if x is 0:
                continue
            elif x is not 0:
                p = x; break
        data = data[::-1]
        data = data[p:]
        return data[::-1]

    @staticmethod
    def unblock(data, size=16):
        """ Unblock binary data
        :param bytes data: Binary data to split into blocks
        :param int size: Block size
        :return: Blocked binary data """
        # Return 64-bit blocks from data
        return [data[x:x + size] for x in range(0, len(data), size)]

    @staticmethod
    def RotWord(word):
        """ Takes a word [a0, a1, a2, a3] as input and perform a
        cyclic permutation that returns the word [a1, a2, a3, a0].
        :param str word: Row within State Matrix
        :return: Circular byte left shift """
        return int(word[2:] + word[0:2], 16)

    @staticmethod
    def StateMatrix(state):
        """ Formats a State Matrix str to a properly formatted list.
        :param str state: String State Matrix
        :return: Formatted State Matrix """
        new_state = []
        split = re.findall('.' * 2, state)
        for x in range(4):
            new_state.append(split[0:4][x]); new_state.append(split[4:8][x])
            new_state.append(split[8:12][x]); new_state.append(split[12:16][x])
        return new_state

    @staticmethod
    def RevertStateMatrix(state):
        """ Reverts State Matrix format as str
        :param list state: Final State Matrix
        :return: Reverted State Matrix """
        columns = [state[x:x + 4] for x in range(0, 16, 4)]
        return ''.join(''.join([columns[0][x], columns[1][x], columns[2][x], columns[3][x]]) for x in range(4))

    @staticmethod
    def galois(a, b):
        """ Galois multiplication of 8 bit characters a and b
        :param a: State Matrix col or row
        :param b: Fixed number
        :return: Galois field GF(2^8) """
        p = 0
        for counter in range(8):
            if b & 1: p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            # keep a 8 bit
            a &= 0xFF
            if hi_bit_set:
                a ^= 0x1b
            b >>= 1
        return p

    @staticmethod
    def AddRoundKey(state, key):
        """ Round Key is added to the State using an XOR operation.
        :param list state: State Matrix
        :param list key: Round Key
        :return: Hex values of XOR operation """
        return ['%02x' % (int(state[x], 16) ^ int(key[x], 16)) for x in range(16)]

    def ShiftRows(self, state, isInv):
        """ Changes the State by cyclically shifting the last
        three rows of the State by different offsets.
        :param list state: State Matrix
        :param isInv: Encrypt or Decrypt
        :return: Shifted state by offsets [0, 1, 2, 3] """
        offset = 0
        if isInv: state = re.findall('.' * 2, self.RevertStateMatrix(state))
        for x in range(0, 16, 4):
            state[x:x + 4] = state[x:x + 4][offset:] + state[x:x + 4][:offset]
            if not isInv:
                offset += 1
            elif isInv:
                offset -= 1
        if isInv: return self.StateMatrix(''.join(state))
        return state

    def SubWord(self, byte):
        """ Key Expansion routine that takes a four-byte
        input word and applies an S-box substitution.
        :param int byte: Output from the circular byte left shift
        :return: Substituted bytes through sbox """
        return ((self.sbox[(byte >> 24 & 0xff)] << 24) + (self.sbox[(byte >> 16 & 0xff)] << 16) +
                (self.sbox[(byte >> 8 & 0xff)] << 8) + self.sbox[byte & 0xff])

    def SubBytes(self, state, isInv):
        """  Transforms the State Matrix using a nonlinear byte S-box
        that operates on each of the State bytes independently.
        :param state: State matrix input
        :param isInv: Encrypt or decrypt mode
        :returns: Byte substitution from the state matrix """
        if not isInv: return ['%02x' % self.sbox[int(state[x], 16)] for x in range(16)]
        elif isInv: return ['%02x' % self.rsbox[int(state[x], 16)] for x in range(16)]

    # noinspection PyAssignmentToLoopOrWithParameter
    def MixColumns(self, state, isInv):
        """ Operates on the State column-by-column, treating each column as
        a four-term polynomial. The columns are considered as polynomials
        over GF(2^8) and multiplied modulo x^4 + 1 with a fixed polynomial a(x).
        :param state: State Matrix input
        :param isInv: Encrypt or decrypt mode
        :return:
        """
        if isInv: fixed = [14, 9, 13, 11]; state = self.StateMatrix(''.join(state))
        else: fixed = [2, 1, 1, 3]
        columns = [state[x:x + 4] for x in range(0, 16, 4)]
        row = [0, 3, 2, 1]
        col = 0
        output = []
        for _ in range(4):
            for _ in range(4):
                # noinspection PyTypeChecker
                output.append('%02x' % (
                    self.galois(int(columns[row[0]][col], 16), fixed[0]) ^
                    self.galois(int(columns[row[1]][col], 16), fixed[1]) ^
                    self.galois(int(columns[row[2]][col], 16), fixed[2]) ^
                    self.galois(int(columns[row[3]][col], 16), fixed[3])))
                row = [row[-1]] + row[:-1]
            col += 1
        return output

    def Cipher(self, expandedKey, data):
        """ At the start of the Cipher, the input is copied to the
        State Matrix. After an initial Round Key addition, the
        State Matrix is transformed by implementing a round function
        10, 12, or 14 times (depending on the key length), with the final
        round differing slightly from the first Nr -1 rounds. The final
        State Matrix is then copied as the output.
        :param list expandedKey: The expanded key schedule
        :param str data: Hex string to encrypt
        :return: Encrypted data as a Hex string """
        state = self.AddRoundKey(self.StateMatrix(data), expandedKey[0])
        for r in range(self.Nr - 1):
            if not self.byteSubId: state = self.SubBytes(state, False)
            if not self.shiftRowsId: state = self.ShiftRows(state, False)
            if not self.mixColumnsId: state = self.StateMatrix(''.join(self.MixColumns(state, False)))
            state = self.AddRoundKey(state, expandedKey[r + 1])

        if not self.byteSubId: state = self.SubBytes(state, False)
        if not self.shiftRowsId: state = self.ShiftRows(state, False)
        state = self.AddRoundKey(state, expandedKey[self.Nr])
        return self.RevertStateMatrix(state)

    def InvCipher(self, expandedKey, data):
        state = self.AddRoundKey(re.findall('.' * 2, data), expandedKey[self.Nr])

        for r in range(self.Nr - 1):
            if not self.shiftRowsId: state = self.ShiftRows(state, True)
            if not self.byteSubId: state = self.SubBytes(state, True)
            state = self.AddRoundKey(state, expandedKey[-(r + 2)])
            if not self.mixColumnsId: state = self.MixColumns(state, True)

        if not self.shiftRowsId: state = self.ShiftRows(state, True)
        if not self.byteSubId: state = self.SubBytes(state, True)
        state = self.AddRoundKey(state, expandedKey[0])
        return ''.join(state)

    def ExpandKey(self, key):
        """ Takes the Cipher Key and performs a Key Expansion routine to
        generate a key schedule thus generating a total of Nb (Nr + 1) words.
        :param str key: 128, 192, 256 bit Cipher Key
        :return: Expanded Cipher Keys """
        w = ['%08x' % int(x, 16) for x in re.findall('.' * 8, key)]

        i = self.Nk
        while i < self.Nb * (self.Nr + 1):
            temp = w[i - 1]
            if i % self.Nk is 0:
                temp = '%08x' % (self.SubWord(self.RotWord(temp)) ^ (self.rcon[i // self.Nk] << 24))
            elif self.Nk > 6 and i % self.Nk is 4:
                temp = '%08x' % self.SubWord(int(temp, 16))
            w.append('%08x' % (int(w[i - self.Nk], 16) ^ int(temp, 16)))
            i += 1

        return [self.StateMatrix(''.join(w[x:x + 4])) for x in range(0, len(w), self.Nk)]

    def key_handler(self, key, isInv):
        """ Gets the key length and sets Nb, Nk, Nr accordingly.
        :param str key: 128, 192, 256 bit Cipher Key
        :param isInv: Encrypt or decrypt mode
        :return: Expanded Cipher Keys """
        # 128-bit key
        if len(key) is 32:
            self.Nb = 4; self.Nk = 4; self.Nr = 10
        # 192-bit key
        elif len(key) is 48:
            self.Nb = 4; self.Nk = 6; self.Nr = 12
        # 256-bit key
        elif len(key) is 64:
            self.Nb = 4; self.Nk = 8; self.Nr = 14
        # Raise error on invalid key size
        else: raise AssertionError("%s Is an invalid Key!\nUse a 128-bit, 192-bit or 256-bit key!" % key)
        # Return the expanded key
        if not isInv: return self.ExpandKey(key)
        # Return the inverse expanded key
        if isInv: return [re.findall('.' * 2, self.RevertStateMatrix(x)) for x in self.ExpandKey(key)]

    def aes_main(self, data, key, isInv):
        """ Handle encryption and decryption modes
        :param data: Data to be handled (type defined by input type)
        :param key: Cipher Key to be expanded
        :param isInv: Encrypt or decrypt mode
        :return: Data as hex string or binary data (defined by output type) """
        # Get the expanded key set
        expanded_key = self.key_handler(key, isInv)
        # Encrypt using ECB mode
        if self.mode is 'ecb': return self.ecb(data, expanded_key, isInv)
        # Encrypt using CBC mode
        elif self.mode is 'cbc': return self.cbc(data, expanded_key, isInv)
        # Raise error on invalid mode
        else: raise AttributeError("\n\n\tSupported AES Modes of Operation are ['ecb', 'cbc']")

    def encryption(self, data, key):
        """ Main AES Encryption function
        :param data: Input for encryption
        :param key: Encryption key
        :return: Encrypted data """
        return self.aes_main(data, key, False)

    def decryption(self, data, key):
        """ Main AES Decryption function
        :param data: Input for decryption
        :param key: Decryption key
        :return: Decrypted data """
        return self.aes_main(data, key, True)

    @staticmethod
    def xor(first, last):
        """ Xor method for CBC usage    
    
        :param first: first encrypted block
        :param last: last encrypted block
        :return: Xor output of two blocks """
        first = re.findall('.' * 2, first)
        last = re.findall('.' * 2, last)
        return ''.join('%02x' % (int(first[x], 16) ^ int(last[x], 16)) for x in range(16))

    def cbc(self, data, expanded_key, isInv):
        """ CBC mode:
        In CBC mode, each block of plaintext is XORed with the
        previous ciphertext block before being encrypted.
        Denoted as:
            Encryption: Ci = Ek(Pi xor C(i-1)) and C0 = IV
            Decryption: Pi = Dk(Ci) xor C(i-1) and C0 = IV
        :param data: Data to be encrypted (type defined by input type)
        :param expanded_key: The AES expanded key set
        :param isInv:
        :return: Data as string or binary data (defined by output type)"""
        if self.iv is None: raise AttributeError("No Iv found!")
        if self.input is 'hex':
            if type(data) is not list: data = data.split()
            blocks = [self.iv]; last = [self.iv] + data
            if not isInv:
                [blocks.append(self.Cipher(expanded_key, self.xor(blocks[-1], x))) for x in data]
                return blocks[1:]
            elif isInv:
                return ''.join([self.xor(self.InvCipher(expanded_key, data[x]), last[x]) for x in range(len(data))])
        elif self.input is 'data':
            if not isInv:
                data = re.findall('.' * 32, binascii.hexlify(self.pad(data)).decode()); blocks = [self.iv]
                [blocks.append(self.Cipher(expanded_key, self.xor(blocks[-1], x))) for x in data]
                return b''.join(binascii.unhexlify(x.encode()) for x in blocks[1:])
            elif isInv:
                data = re.findall('.' * 32, binascii.hexlify(data).decode()); last = [self.iv] + data
                return self.unpad(b''.join(binascii.unhexlify(x.encode()) for x in [self.xor(
                    self.InvCipher(expanded_key, data[x]), last[x]) for x in range(len(data))]))

        # Raise error on invalid input
        else: raise AttributeError("\n\n\tSupported AES inputs are ['hex', 'data']")

    def ecb(self, data, expanded_key, isInv):
        """ ECB mode:
        The simplest of the encryption modes is the Electronic
        Codebook (ECB) mode. The message is divided into blocks,
        and each block is encrypted separately.
        :param isInv: 
        :param data: Data to be encrypted (type defined by input type)
        :param expanded_key: The AES expanded key set
        :return: Data as string or binary data (defined by output type)"""
        # Encrypt hex string data
        if self.input is 'hex':
            if not isInv: return self.Cipher(expanded_key, data)
            elif isInv: return self.InvCipher(expanded_key, data)
        # Encrypt an text string
        elif self.input is 'text':
            if not isInv: return self.Cipher(expanded_key, ''.join('%02x' % x for x in self.pad(data.encode())))
            elif isInv: return str(self.unpad(binascii.unhexlify(self.InvCipher(expanded_key, data).encode())))[2:-1]
        # Encrypt a stream of binary data
        elif self.input is 'data':
            if not isInv: return b''.join(binascii.unhexlify(self.Cipher(
                expanded_key, str(binascii.hexlify(x))[2:-1]).encode()) for x in self.unblock(data))
            if isInv: return b''.join(binascii.unhexlify(self.InvCipher(
                expanded_key, str(binascii.hexlify(x))[2:-1]).encode()) for x in self.unblock(data))
        # Raise error on invalid input
        else: raise AttributeError("\n\n\tSupported Input types are ['hex', 'text', 'data']")


def part1 (M, K, byteSubId):

    LENGTH = 128
    hex = lambda n: f'{n:032x}'
    aes = AES(mode='ecb', input_type='hex', byteSubId = byteSubId)
    C = aes.encryption(M, K)

    Mint = int(M, 16)
    Cint = int(C, 16)

    for i in range(LENGTH):
        Mint_i = Mint ^ (1 << (LENGTH - 1 - i))
        M_i = hex(Mint_i)

        C_i = aes.encryption(M_i, K)
        Cint_i = int(C_i, 16)

        for j in range(i + 1, LENGTH):
            Mint_j = Mint ^ (1 << (LENGTH - 1 - j))
            M_j = hex(Mint_j)

            C_j = aes.encryption(M_j, K)
            Cint_j = int(C_j, 16)

            Mint_ij = Mint ^ ((1 << (LENGTH - 1 - i)) | (1 << (LENGTH - 1 - j)))
            M_ij = hex(Mint_ij)

            C_ij = aes.encryption(M_ij, K)
            Cint_ij = int(C_ij, 16)

            if Cint != Cint_i ^ Cint_j ^ Cint_ij: return False
    
    return True

def part2 (M, K, shiftRowsId):

    LENGTH = 128
    Mint = int(M, 16)
    hex = lambda n: f'{n:032x}'
    aes = AES(mode='ecb', input_type='hex', shiftRowsId = shiftRowsId)

    for i in range(LENGTH):
        Mint = Mint - random.randint(1, 2 ** LENGTH)
        M = hex(Mint)

        C = aes.encryption(M, K)
        Cint = int(C, 16)

        Mint_i = Mint ^ (1 << (LENGTH - 1 - i))
        M_i = hex(Mint_i)

        C_i = aes.encryption(M_i, K)
        Cint_i = int(C_i, 16)

        print(hex(Cint ^ Cint_i))

def part3 (M, K, mixColumnsId):

    LENGTH = 128
    Mint = int(M, 16)
    hex = lambda n: f'{n:032x}'
    aes = AES(mode='ecb', input_type='hex', mixColumnsId = mixColumnsId)

    for i in range(LENGTH):
        Mint = Mint - random.randint(1, 2 ** LENGTH)
        M = hex(Mint)

        C = aes.encryption(M, K)
        Cint = int(C, 16)

        Mint_i = Mint ^ (1 << (LENGTH - 1 - i))
        M_i = hex(Mint_i)

        C_i = aes.encryption(M_i, K)
        Cint_i = int(C_i, 16)

        print(hex(Cint ^ Cint_i))

def count_ones_binary (B):
    total = 0
    while B != 0: 
        total += B % 2
        B >>= 1
    return total

def index_positions_changed (B):
    idx, i = [], 0
    while B != 0:
        if B % 2 == 1: idx.append(i)
        B >>= 1
        i += 1
    return idx

def bits_change_statistics(M, K, 
    changeK = False, 
    byteSubId = False,
    shiftRowsId = False,
    mixColumnsId = False):

    bits = []
    positions = {}

    LENGTH = 128
    hex = lambda n: f'{n:032x}'
    aes = AES(mode='ecb', 
            input_type='hex', 
            byteSubId = byteSubId,
            shiftRowsId = shiftRowsId,
            mixColumnsId = mixColumnsId)

    C = aes.encryption(M, K)
    Cint = int(C, 16)

    for i in range(LENGTH):

        if not changeK: 
            Mint = int(M, 16)
            Mint_i = Mint ^ (1 << (LENGTH - 1 - i))
            M_i = hex(Mint_i)
            C_i = aes.encryption(M_i, K)
        else: 
            Kint = int(K, 16)
            Kint_i = Kint ^ (1 << (LENGTH - 1 - i))
            K_i = hex(Kint_i)
            C_i = aes.encryption(M, K_i)

        Cint_i = int(C_i, 16)

        idx_positions = index_positions_changed(Cint ^ Cint_i)
        bits.append(count_ones_binary(Cint ^ Cint_i))

        for j in idx_positions:
            if j in positions:
                positions[j] += 1
            else:
                positions[j] = 1

    fig, ax = plt.subplots(1, 2, figsize=(10,5))
    plt.box(False)
    print(positions)
    ax[0].hist(bits, edgecolor = 'white',  linewidth = 0.5, bins = 10)
    ax[0].set_xlim(xmin = 0, xmax = 128)
    ax[0].set_title("Histogram of total number of bits\nchanged on each modification")
    ax[0].set_xlabel("Bits changed")
    ax[0].set_ylabel("Times")

    ax[1].bar(positions.keys(), positions.values())
    ax[1].set_title("Histogram of positions that\nchange on each modification")
    ax[1].set_xlabel("Bit position")
    ax[1].set_ylabel("Number of changes")
    
    plt.show()

def part4 (M):
    LENGTH = 128
    hex = lambda n: f'{n:032x}'
    aes = AES(mode='ecb', input_type='hex')
    BOUND = 2 ** LENGTH

    max_zeros = 0
    best_K = None

    try:
        for i in range(BOUND):
            Kint = random.randint(1, BOUND)
            K = hex(Kint)

            C = aes.encryption(M, K)
            Cint = int(C, 16)

            zeros_found = bin(Cint)[2:].count('0')
            if zeros_found > max_zeros:
                max_zeros = zeros_found
                best_K = K
                if max_zeros % 5 == 0: print(f'{max_zeros} found up to now.')
            
    except KeyboardInterrupt:
        print(f'Interrupted on iteration {i}')
        print(f'{bin(Cint)[2:]}\n')

    return (best_K, max_zeros, i)

def part5 (K):
    LENGTH = 128
    hex = lambda n: f'{n:032x}'
    aes = AES(mode='ecb', input_type='hex')
    BOUND = 2 ** LENGTH

    max_zeros = 0
    best_M = None

    try:
        for i in range(BOUND):
            Mint = random.randint(1, BOUND)
            M = hex(Mint)

            C = aes.encryption(M, K)
            Cint = int(C, 16)

            zeros_found = bin(Cint)[2:].count('0')
            if zeros_found > max_zeros:
                max_zeros = zeros_found
                best_M = M
                if max_zeros % 5 == 0: print(f'{max_zeros} found up to now.')
            
    except KeyboardInterrupt:
        print(f'Interrupted on iteration {i}')
        print(f'{bin(Cint)[2:]}\n')

    return (best_M, max_zeros, i)

def part6 ():
    LENGTH = 128
    hex = lambda n: f'{n:032x}'
    aes = AES(mode='ecb', input_type='hex')
    BOUND = 2 ** LENGTH

    max_zeros = 0
    best_M, best_K = None, None

    try:
        for i in range(BOUND):
            Mint, Kint = random.randint(1, BOUND), random.randint(1, BOUND)
            M, K = hex(Mint), hex(Kint)

            C = aes.encryption(M, K)
            Cint = int(C, 16)

            zeros_found = bin(Cint)[2:].count('0')
            if zeros_found > max_zeros:
                max_zeros = zeros_found
                best_M, best_K = M, K
                if max_zeros % 5 == 0: print(f'{max_zeros} found up to now.')
            
    except KeyboardInterrupt:
        print(f'Interrupted on iteration {i}')
        print(f'{bin(Cint)[2:]}\n')

    return (best_M, best_K, max_zeros, i)

if __name__ == "__main__":   
    # Set seed for reproducibility
    random.seed(123)

    # Test vector 128-bit key
    K = '000102030405060708090a0b0c0d0e0f'
    M = '00112233445566778899aabbccddeeff'

    """ PART 2.1 ====================== """
    
    """ PART 2.1.1 """
    # Amb byteSub Id = True, dóna True
    print(part1(M, K, True))

    # Amb byteSub original dóna False
    print(part1(M, K, False))

    """ PART 2.1.2 """
    # ShiftRows
    part2(M, K, True)

    """ PART 2.1.3 """
    # MixColumns
    part3(M, K, True)

    """ PART 2.2 ====================== """
    bits_change_statistics(M, K, changeK = True, 
                            byteSubId = False,
                            shiftRowsId = False,
                            mixColumnsId = False)

    """ PART 2.3 ====================== """
    M = '00112233445566778899aabbccddeeff'
    K, zeros, i = part4(M)
    print(f'Max zeros found: {zeros} with key {K} with {i} iterations')

    """
    Interrupted on iteration 115731
    11100000101110010111101100101010110101000110001111010011010001110001111011010101110011111001010010111110110011111101100110000010
    Max zeros found: 86 with key d76808319e9b76f72da0efe311658d94 with 115731 iterations
    """

    K = '0123456789abcdeffedcba9876543210'
    M, zeros, i = part5(K)
    print(f'Max zeros found: {zeros} with message {M} with {i} iterations') 

    """
    10110110011011001111101101011001001110111110011110111101010001110100010110101011011100110110001101101001110110000010110000100100
    Max zeros found: 87 with message 5d93c021aecad160e12bf4d8d484241e with 121980 iterations
    """ 

    M, K, zeros, i = part6()
    print(f'Max zeros found: {zeros} with message {M} and key {K} with {i} iterations') 

    """
    Interrupted on iteration 164457
    10001010011000101000000010001111011101111110100100010111011000110000011000010010111101011111001110000011011010100000001111100100
    Max zeros found: 88 with message 696dc1e488e6145b57aa0d4a0dab5180 and key 6af59f3bc7e2f30b757e1c048824990b with 164457 iterations
    """ 


    
    


