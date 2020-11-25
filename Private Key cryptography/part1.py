
# LAB 2 ~ PART 1 ~ MARGARITA GELETA
# Info http://www.cs.utsa.edu/~wagner/laws/FFM.html

from time import time

def GF_product_p (a, b):
    """
    Entrada: a i b elements del cos representat per enters entre 0 i 255; 
    Sortida: un element del cos representat per un enter entre 0 i 255 que es 
    el producte en el cos de a i b fent servir la deﬁnicio en termes de polinomis.
    """
    res = 0
    while b > 0:
        if b % 2 != 0: res ^= a
        # Shift to next pos
        a <<= 1
        # If there is carry
        if a > 0xff: a ^= 0x12d
        # Delete last pos in b
        b >>= 1 
    return res

def GF_es_generador (a):
    """
    Entrada: a element del cos representat per un enter entre 0 i 255; 
    Sortida: True si a es generador del cos, False si no ho es.
    """
    if a == 0: return False
    aux = 1
    for i in range(1, 0xff + 1):
        aux = GF_product_p(a, aux)
        # If we find a 1 before pos 0xff not a generator
        if aux == 1: return True if i == 0xff else False
    return False

def GF_tables (a = 2):
    """
    Entrada: 
    Sortida: dues taules (exponencial i logaritme), una que a la posicio i tingui 
    a = g^i i una altra que a la posicio a tingui i tal que a = g^i. 
    (g generador del cos ﬁnit del cos representat pel menor enter entre 0 i 255.)
    """
    assert GF_es_generador(a), 'Not a generator!'
    
    aux = 1
    EXP_TABLE = [None] * (0xff + 1)
    LOG_TABLE = EXP_TABLE.copy()

    for i in range(len(EXP_TABLE)):
        EXP_TABLE[i] = aux
        LOG_TABLE[aux] = i
        aux = GF_product_p(aux, a)

    return EXP_TABLE, LOG_TABLE

def GF_product_t (a, b):
    """
    Entrada: a i b elements del cos representat per enters entre 0 i 255; 
    Sortida: un element del cos representat per un enter entre 0 i 255 que 
    es el producte en el cos de a i b fent servir la les taules exponencial 
    i logaritme.
    """
    exp = 0
    if a == 0 or b == 0: return 0
    # Find the exponent
    exp = LOG_TABLE[a] + LOG_TABLE[b] 
    # If the exponent is larger 0xff, take modulo
    if exp > 0xff: exp %= 0xff
    return EXP_TABLE[exp]

def GF_invers (a):
    """
    Entrada: a element del cos representat per un enter entre 0 i 255;
    Sortida: 0 si a=0x00, invers d’a en el cos si a!=0x00 representat per un 
    enter entre 1 i 255.
    """
    assert a > 0 and a <= 0xff, 'Invalid'
    
    return EXP_TABLE[0xff - LOG_TABLE[a]]

if __name__ == "__main__":

    # Generate tables

    EXP_TABLE, LOG_TABLE = GF_tables ()

    hex = lambda n: f'{n:016x}'
    print(hex(301))
    print(GF_product_p (77, 5))
    # Sanity checks
