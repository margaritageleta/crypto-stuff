import numpy as np

def decrypt_scytale(cypher, key):
    matrix = np.matrix(list(cypher))
    matrix_len = len(cypher)

    matrix = matrix.reshape((key, int(len(cypher) / key)))
    for row in matrix.T:
        print(''.join(np.array(row)[0]))

def scytale_exh(cypher, range):
    matrix = np.matrix(list(cypher))
    previous_ratio = 0

    for i in range:
        matrix_len = len(cypher)
        pad = 0

        while matrix_len % i != 0: 
            pad += 1
            matrix_len += 1

        if previous_ratio * i == matrix_len: continue
        else: 
            previous_ratio =  matrix_len / i
            print(5*'-' + f'Using scytale length {i}' + 5*'-')
            submatrix = np.matrix(matrix.tolist()[0] + np.empty((1,pad), dtype="<U0").tolist()[0])
            submatrix = submatrix.reshape((i, int(matrix_len / i)))
            
            num_rows = 2
            for row in submatrix.T:
                print(''.join(np.array(row)[0]))
                num_rows -= 1
                if num_rows == 0: break
            print('\n')

if __name__ == "__main__":

    cypher = open('Escitalo', mode='r').read()
    
    scytale_exh(cypher, range(2, 4000))

    #decrypt_scytale(cypher, 3513)