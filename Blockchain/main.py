from blockchain import rsa_key, transaction, block_chain
import bs4 as bs
import requests
import hashlib
from time import time
import pickle

def test_TXR():
    uri = "https://en.wikipedia.org/wiki/Blockchain"
    site = requests.get(uri)
    soup = bs.BeautifulSoup(site.content,'html.parser')   
    i = 0
    words = []
    for x in soup.find_all('span'):
        if i < 100:
            words.append(x.text)
            i += 1
        else:
            print('Found 100 texts')
            break

    assert(len(words) == 100)

    messages = [int(hashlib.sha256(words[i].encode()).hexdigest(), 16) for i in range(100)]

    keys = [512, 1024, 2048, 4096]
    
    output = "Key,Time without TXR,Time with TXR\n"

    for modulo in keys:
        RSA = rsa_key(bits_modulo = modulo)
        
        now = time()
        for message in messages:
            RSA.sign_slow(message)
        slow_time_signatures = time() - now

        now = time()
        for message in messages:
            RSA.sign(message)
        time_signatures = time() - now

        output += f"{modulo},{slow_time_signatures},{time_signatures}\n"

        print(f'key: {modulo} slow: {slow_time_signatures} fast: {time_signatures}')

    with open("table.csv", "w") as f:
        f.write(output)

def create_blockchain_100():
    RSA = rsa_key()
    num_blocks = 100

    now = time()

    transactions = map(lambda i: transaction(int(hashlib.sha256(f"Transaction #{i}".encode()).hexdigest(), 16), RSA), range(100))
    blockChain = block_chain(next(transactions)) 
    
    for _ in range(1, num_blocks): 
        blockChain.add_block(next(transactions))
        print(f'New block from transaction #{_ + 1} added!')

    with open('100_blocks.pickle', 'wb') as f:
        pickle.dump(blockChain, f)

    print(f"Verification: {blockChain.verify()}\nTime elapsed: {time() - now}")

def create_wrong_blockchain_100():
    DNI = 19
    RSA = rsa_key()
    num_blocks = 100

    now = time()

    transactions = map(lambda i: transaction(int(hashlib.sha256(f"Transaction #{i}".encode()).hexdigest(), 16), RSA), range(100))
    blockChain = block_chain(next(transactions)) 
    
    for _ in range(1, DNI): 
        blockChain.add_block(next(transactions))
        print(f'New block from transaction #{_ + 1} added!')
    print(f"Pre-verification: {blockChain.verify()}")
    for _ in range(DNI, num_blocks): 
        print(f'Wrong block from transaction #{_ + 1} added!')
        blockChain.add_wrong_block(next(transactions))

    with open(f'100_blocks_{DNI}_wrong.pickle', 'wb') as f:
        pickle.dump(blockChain, f)

    print(f"Verification: {blockChain.verify()}\nTime elapsed: {time() - now}")

if __name__ == "__main__":
    test_TXR()
    create_blockchain_100()
    create_wrong_blockchain_100()
    