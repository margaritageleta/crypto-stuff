from collections import Counter
from pick import pick
import re, string

ENG = {'E': 529117365, 
    'T': 390965105, 
    'A': 374061888, 
    'O': 326627740, 
    'I': 320410057, 
    'N': 313720540, 
    'S': 294300210, 
    'R': 277000841, 
    'H': 216768975, 
    'L': 183996130, 
    'D': 169330528, 
    'C': 138416451, 
    'U': 117295780, 
    'M': 110504544, 
    'F': 95422055, 
    'G': 91258980, 
    'P': 90376747, 
    'W': 79843664, 
    'Y': 75294515, 
    'B': 70195826, 
    'V': 46337161, 
    'K': 35373464, 
    'J': 9613410, 
    'X': 8369915, 
    'Z': 4975847, 
    'Q': 4550166}

if __name__ == "__main__":

    cypher = open('Cifrado', mode='r').read().replace('\ufeff', '') #.replace('\n', '')

    # Setup English statistics desc
    stats = [k for (k,v) in sorted(ENG.items(), key=lambda item: -item[1])]

    # Setup cypher statistics desc
    # Delete from text punctuation and numbers
    cypher_counter = Counter(re.sub(r'[0-9]+', '', cypher.replace('\n', '').translate(str.maketrans('', '', string.punctuation))))
    cypher_counter.pop(' ', None) # Delete space
    cypher_stats = [k for (k,v) in sorted(cypher_counter.items(), key=lambda item: -item[1])]

    # Setup decoder
    decoder = {}
    alphabet = stats.copy()
    stats_len = len(stats)
    cypher_alphabet = cypher_stats.copy()
    swapped = False

    for i in range(len(stats)):
        title = f"Remaining alphabet in order:    {' '.join(alphabet)}\n" + \
                f"Remaining criptograms in order: {' '.join(cypher_alphabet)}\n\n" + \
                f'Choose substution for {cypher_stats[i]}:\n' + cypher[:500]
        if swapped:
            title = title + '\n\n' + "Previous swap:" + '\n' + swap_text 

        options = [f'Choose by stats ({cypher_stats[i]} => {stats[i]})', 'Choose manually']
        option, index = pick(options, title)

        if index:
            title = f'Choose manually substution for {cypher_stats[i]}:\n' + cypher[:500]
            option, index = pick(alphabet, title)

            cypher = cypher.replace(cypher_stats[i], alphabet[index])
            decoder[cypher_stats[i]] = alphabet[index]

            # Swap symbols
            stats_i, alpha_i = i, stats.index(alphabet[index])
            stats[alpha_i], stats[stats_i] = stats[stats_i], stats[alpha_i]
            alphabet_len = len(alphabet)
            alphabet[alpha_i - (stats_len - alphabet_len)], alphabet[stats_i - (stats_len - alphabet_len)] = alphabet[stats_i - (stats_len - alphabet_len)], alphabet[alpha_i - (stats_len - alphabet_len)]

            # Show swap message
            swapped = True
            swap_text = f'({stats[alpha_i]}, {cypher_alphabet[stats_i - (stats_len - alphabet_len)]}) ==> ({stats[alpha_i]},{cypher_alphabet[alpha_i - (stats_len - alphabet_len)]})\n' + \
                f'({stats[stats_i]}, {cypher_alphabet[alpha_i - (stats_len - alphabet_len)]}) ==> ({stats[stats_i]},{cypher_alphabet[stats_i - (stats_len - alphabet_len)]})\n'
            
            # Remove used symbols
            alphabet.remove(stats[i])
            cypher_alphabet.remove(cypher_stats[i])

        else:
            # Decode criptogram
            cypher = cypher.replace(cypher_stats[i], stats[i])
            decoder[cypher_stats[i]] = stats[i]
            # Remove from alphabets used
            alphabet.remove(stats[i])
            cypher_alphabet.remove(cypher_stats[i])

            swapped = False
    
    # Save the decrypted text
    with open("decryption.txt", "w") as f:
        f.write(cypher)
    
    # Show decoder dictionary
    print(decoder)





