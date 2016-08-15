

alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

if bytes == str:  # python2
    iseq = lambda s: map(ord, s)
    bseq = lambda s: ''.join(map(chr, s))
    buffer = lambda s: s
else:  # python3
    iseq = lambda s: s
    bseq = bytes
    buffer = lambda s: s.buffer


def b58encode(input):
    '''Encode a string using Base58'''
    origlen = len(input)
    input = input.lstrip(b'\0')
    newlen = len(input)

    p, acc = 1, 0
    for c in iseq(input[::-1]):
        acc += p * c
        p = p << 8

    result = ''
    while acc > 0:
        acc, mod = divmod(acc, 58)
        result += alphabet[mod]

    return (result + alphabet[0] * (origlen - newlen))[::-1]


def b58decode(input):
    '''Decode a Base58 encoded string'''

    if not isinstance(input, str):
        input = input.decode('ascii')

    origlen = len(input)
    input = input.lstrip(alphabet[0])
    newlen = len(input)

    p, acc = 1, 0
    for c in input[::-1]:
        acc += p * alphabet.index(c)
        p *= 58

    result = []
    while acc > 0:
        acc, mod = divmod(acc, 256)
        result.append(mod)

    return (bseq(result) + b'\0' * (origlen - newlen))[::-1]





