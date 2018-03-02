import itertools, re
import vigenereCipher, pyperclip, freqAnalysis, detectEnglish

LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
SILENT_MODE = False # if set to True, program doesn't print attempts
NUM_MOST_FREQ_LETTERS = 4 # asumsi panjang key yg sering muncul 
MAX_KEY_LENGTH = 16 # asumsi panjang maksimal key
NONLETTERS_PATTERN = re.compile('[^A-Z]')


def main():
    ciphertext = """ks syl jiolwk qqmkrkq ix hxhilkwhfgmqicfiqa sgl lmpw ks nlmki rijti fbwji iiju jal gei yijv xugw ;)
"""
    hackedMessage = hackVigenere(ciphertext)

    if hackedMessage != None:
        print('PESAN TERSEMBUNYI TERBONGKAR')
        print(hackedMessage)
        pyperclip.copy(hackedMessage)
    else:
        print('Gagal')


def findRepeatSequencesSpacings(message):
    message = NONLETTERS_PATTERN.sub('', message.upper())

    # Mencari kata berulang
    seqSpacings = {} # Menyimpan jarak antar substring yang berulang
    for seqLen in range(3, 6):
        for seqStart in range(len(message) - seqLen):
            # Menentukan kata yang berulang
            seq = message[seqStart:seqStart + seqLen]

            # Mencari kata yang berulang dalam pesan
            for i in range(seqStart + seqLen, len(message) - seqLen):
                if message[i:i + seqLen] == seq:
                    # Menemukan kata yang berulang
                    if seq not in seqSpacings:
                        seqSpacings[seq] = []

                    # Memasukkan jarak antar kata
                    seqSpacings[seq].append(i - seqStart)
    return seqSpacings


def getUsefulFactors(num):
    if num < 2:
        return [] # factor dari nilai kurang dari 2 tidak dianggap

    factors = [] # Menyimpan nilai faktor

    # Ketika menemukan faktor, lalu kita mengecek yang faktornya diatas MAX_KEY_LENGTH.
    for i in range(2, MAX_KEY_LENGTH + 1):
        if num % i == 0:
            factors.append(i)
            factors.append(int(num / i))
    if 1 in factors:
        factors.remove(1)
    return list(set(factors))


def getItemAtIndexOne(x):
    return x[1]


def getMostCommonFactors(seqFactors):
    # Pertama, menghitung faktor yang sering muncul
    factorCounts = {} # key is a factor, value is how often if occurs

    for seq in seqFactors:
        factorList = seqFactors[seq]
        for factor in factorList:
            if factor not in factorCounts:
                factorCounts[factor] = 0
            factorCounts[factor] += 1

    # Kedua, masukkan nilai faktor dan jumlahnya ke dalam list
    factorsByCount = []
    for factor in factorCounts:
        # Kecuali factor yang lebih dari MAX_KEY_LENGTH
        if factor <= MAX_KEY_LENGTH:
            # factorsByCount is a list of tuples: (factor, factorCount)
            # factorsByCount has a value like: [(3, 497), (2, 487), ...]
            factorsByCount.append( (factor, factorCounts[factor]) )

    # Urutkan list berdasarkan jumlah
    factorsByCount.sort(key=getItemAtIndexOne, reverse=True)

    return factorsByCount


def kasiskiExamination(ciphertext):
    repeatedSeqSpacings = findRepeatSequencesSpacings(ciphertext)

    seqFactors = {}
    for seq in repeatedSeqSpacings:
        seqFactors[seq] = []
        for spacing in repeatedSeqSpacings[seq]:
            seqFactors[seq].extend(getUsefulFactors(spacing))

    factorsByCount = getMostCommonFactors(seqFactors)

    allLikelyKeyLengths = []
    for twoIntTuple in factorsByCount:
        allLikelyKeyLengths.append(twoIntTuple[0])

    return allLikelyKeyLengths


def getNthSubkeysLetters(n, keyLength, message):
    # Mencoba setiap kata ke-N dengan panjang keyLength dalam pesan
   
    # Menggunakan regular expression untuk menghilangkan karakter yang bukan huruf.
    message = NONLETTERS_PATTERN.sub('', message)

    i = n - 1
    letters = []
    while i < len(message):
        letters.append(message[i])
        i += keyLength
    return ''.join(letters)


def attemptHackWithKeyLength(ciphertext, mostLikelyKeyLength):
    # menentukan huruf yang mirip pada setiap kata dalam kunci
    ciphertextUp = ciphertext.upper()
   
    allFreqScores = []
    for nth in range(1, mostLikelyKeyLength + 1):
        nthLetters = getNthSubkeysLetters(nth, mostLikelyKeyLength, ciphertextUp)

        freqScores = []
        for possibleKey in LETTERS:
            decryptedText = vigenereCipher.decryptMessage(possibleKey, nthLetters)
            keyAndFreqMatchTuple = (possibleKey, freqAnalysis.englishFreqMatchScore(decryptedText))
            freqScores.append(keyAndFreqMatchTuple)
        # mengurutkan score
        freqScores.sort(key=getItemAtIndexOne, reverse=True)

        allFreqScores.append(freqScores[:NUM_MOST_FREQ_LETTERS])

    if not SILENT_MODE:
        for i in range(len(allFreqScores)):
            # use i + 1 so the first letter is not called the "0th" letter
            print('Possible letters for letter %s of the key: ' % (i + 1), end='')
            for freqScore in allFreqScores[i]:
                print('%s ' % freqScore[0], end='')
            print() # print a newline

    #coba kombinasi yang mirip setiap formasi
    for indexes in itertools.product(range(NUM_MOST_FREQ_LETTERS), repeat=mostLikelyKeyLength):
        
        possibleKey = ''
        for i in range(mostLikelyKeyLength):
            possibleKey += allFreqScores[i][indexes[i]][0]

        if SILENT_MODE:
            print('Mencoba dengan Kata Kunci: %s' % (possibleKey))

        decryptedText = vigenereCipher.decryptMessage(possibleKey, ciphertextUp)

        if detectEnglish.isEnglish(decryptedText):
           
            origCase = []
            for i in range(len(ciphertext)):
                if ciphertext[i].isupper():
                    origCase.append(decryptedText[i].upper())
                else:
                    origCase.append(decryptedText[i].lower())
            decryptedText = ''.join(origCase)


            return decryptedText

    # No English-looking decryption found, so return None.
    return None


def hackVigenere(ciphertext):
    # First, we need to do Kasiski Examination to figure out what the
    # length of the ciphertext's encryption key is.
    allLikelyKeyLengths = kasiskiExamination(ciphertext)
    if not SILENT_MODE:
        keyLengthStr = ''
        for keyLength in allLikelyKeyLengths:
            keyLengthStr += '%s ' % (keyLength)
        print('PANJANG KATA YANG SAMA: ' + keyLengthStr + '\n')

    for keyLength in allLikelyKeyLengths:
        if not SILENT_MODE:
            print('Mencoba dengan kata kunci dengan panjang %s :' % (keyLength))
        hackedMessage = attemptHackWithKeyLength(ciphertext, keyLength)
        if hackedMessage != None:
            break

    # If none of the key lengths we found using Kasiski Examination
    # worked, start brute-forcing through key lengths.
    if hackedMessage == None:
        if not SILENT_MODE:
            print('')
        for keyLength in range(1, MAX_KEY_LENGTH + 1):
            # don't re-check key lengths already tried from Kasiski
            if keyLength not in allLikelyKeyLengths:
                if not SILENT_MODE:
                    print('Mencoba key %s (%s possible keys)...' % (keyLength, NUM_MOST_FREQ_LETTERS ** keyLength))
                hackedMessage = attemptHackWithKeyLength(ciphertext, keyLength)
                if hackedMessage != None:
                    break
    return hackedMessage


# If vigenereHacker.py is run (instead of imported as a module) call
# the main() function.
if __name__ == '__main__':
    main()