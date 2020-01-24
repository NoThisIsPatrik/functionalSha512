#!/usr/bin/python3
__author__ = 'Patrik Lundin'
__license__ = 'LGPL3.0'
__description__ = "A sha512 implementation using only immutable stateless functions in python. Includes likely-overbearing levels of commentary. Came to be written because one of the originators mentioned Excel does heavy anti-brute-force stuff for it's encryption, which turns out to be 100k rounds of sha512. I wondered what, if anything, sha512 does to avoid cycles in the out-to-in dependence cascade, or if there are other potential shortcuts through this (double xors, additions, etc)"

import struct

    # Round constants. The fracion of p**(-2) of the small primes?
    # Something innocent like that (copied from NISTs definitions)
_k = [ 0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817 ] 

    # Mask off to 64 bit word
mask = lambda a : ( a & 0xffffffffffffffff )

    # Rotate right 64 bit
rr = lambda x,y : mask((x >> y) | (x << (64-y))) 

    # Two standard mix functions for the state expand
f0 = lambda w : ( rr(w[-15], 1) ^ rr(w[-15], 8) ^ (w[-15] >> 7) )
f1 = lambda w : ( rr(w[-2], 19) ^ rr(w[-2], 61) ^ (w[-2] >> 6) )

    # Expand 16w state to 80w
expand_state_w = (lambda w : expand_state_w( 
        w + [ mask( w[-16] + f0(w) + w[-7] + f1(w) ) ]  # calc + add next word
        ) if len(w)<80 else w )  # .. until done
    
    # As an aside, this is quite a clever expansion. Each new entry will depend
    # on the entries 16, 15, 7, and 2 words prior to it. Of course, 2 rounds
    # on, *this* will be the "two words prior", which in turn is a mix of 4x
    # others - geometric expansion of input dependence. To make sure we don't
    # accidentally loop onto ourselves and cancel out priors, f0, f1 shuffles
    # the bits up a bit. Actual addition (not "bitwise +", i.e. ^) makes sure
    # tracking any bit forwards will be a pain.

    # Helper func to make word array (from bytes), then get those expanded
expand_state = lambda c: expand_state_w(list(struct.unpack('!16Q', c)))

    # sha512 inner loop operations

    # s0, s1 preset a and e shuffles
s0 = lambda a : rr(a, 28) ^ rr(a, 34) ^ rr(a, 39)
s1 = lambda e : rr(e, 14) ^ rr(e, 18) ^ rr(e, 41)

    # maj, from a, b, c, set each bit to majority value, i.e. whichever
    # there are two of. 
    #  a  00001111
    #  b  00110011
    #  c  01010101
    #  ------------
    # maj 00010111
    # (The or:s can be xor:s, or +:es. Lots of ways to express this)
maj = lambda v : ((v[0] & v[1]) | (v[0] & v[2]) | (v[1] & v[2]))

    # ch, choose bit from f or g based on if e is 0 or 1
    #  e  0000 1111
    #  g  0011 0011
    #  f  0101 0101
    #  -----------
    # ch  0011 0101
    # (again, | can be ^ or +, and lots of other ways to put this)
ch = lambda v : (v[0] & v[1]) | ((~v[0]) & v[2])

    # final two included values each round, including w (from mesg)
    # and _k (round constants). Bit of this and that..
t1 = lambda v,i,w: v[7] + s1(v[4]) + ch(v[4:7]) + _k[i] + w[i]
t2 = lambda v: s0(v[0]) + maj(v)

    # 80 round inner loop, recurisve, add to prior state 
    # (v[] here is variables a-h in the white paper/reference impl)
v80_h = lambda _h,v,i,w : (
    v80_h(
        _h,     # starting state for end addition
        (mask(t1(v,i,w)+t2(v)), v[0], v[1], v[2], mask(v[3] + t1(v,i,w)), v[4], v[5], v[6]),    # v (a-h) next round calcs, mixes, moves, adds..
        i+1,    # loop var
        w       # msg + expansion
    ) if i<80 else vsum(_h,v) # Done? Add it to the starting state
)

    # Add up vectors, like v (aka a-h) and _h
vsum = lambda a,b: [mask(x+y) for x,y in zip(a, b)]

    # Doit! (helper function to put in init states)
do_chunk = lambda c,_h: v80_h( _h, _h, 0, expand_state(c) ) 

    # pad message, +'1' bit, then '0' bits to fit evenly mod 1024 bit w/
    # 128 bit msg length at the end. Make extra chunk if it won't fit. 
pad = lambda m:(
    m +                # Message
    b"\x80" +          # '1' bit (+ 7 '0':bits - whole bytes or GTFO)
    b"\x00"*( 
        (128-16-1) +   # left w/ 16b end-field and the '1' just above
        (128*((len(m)%128)>(128-16-1)))  #  Won't fit? Add more.
        -(len(m)%128)) # all is % 128, and 128-n%128 congrues -n%128
        + (b"\x00"*8)  # (2**64 bytes should be enough for anyone)
        + struct.pack("!Q",len(m)*8)   # That msg len, bits
)

    # Divide msg into chunks, process, and pack up the end result
pr = lambda m, h: ( pr(   # Next round ..
    m[128:],              # .. do the rest (less 128b, aka this chunk)
    do_chunk(m[:128], h)  # Now, do this chunk, figuring out the next stat (h)
    ) if m else struct.pack("!8Q",*h)  # No chunk? Cool, pack up state in bytes
)

    # Finally roll it all up, pad the message and pass init vector
sha512 = lambda m : (pr(
    pad(m),
    ( 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 ) # (Initialization vector per NIST spec)
    )
)

    # Run some test vectors (from nist.gov, reformatted for python use)
    # The final one, 'a'*1000000, will bottom out max_recursion in most
    # setups since it does 
    #   f( rest, state ) => f( rest[size:], do(rest[:size], state) )
    # spawning 1e6//128 == 7.8k depth

def do_some_tests():
    tvs = [
        {"m":"abc", "r256": "ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad", "r512": "ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a 2192992a274fc1a8 36ba3c23a3feebbd 454d4423643ce80e 2a9ac94fa54ca49f"},
        {"m": "", "r256": "e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855", "r512": "cf83e1357eefb8bd f1542850d66d8007 d620e4050b5715dc 83f4a921d36ce9ce 47d0d13c5d85f2b0 ff8318d2877eec2f 63b931bd47417a81 a538327af927da3e"}, 
        {"m": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "r256": "248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1", "r512": "204a8fc6dda82f0a 0ced7beb8e08a416 57c16ef468b228a8 279be331a703c335 96fd15c13b1b07f9 aa1d3bea57789ca0 31ad85c7a71dd703 54ec631238ca3445"}, 
        {"m": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "r256": "cf5b16a7 78af8380 036ce59e 7b049237 0b249b11 e8f07a51 afac4503 7afee9d1", "r512": "8e959b75dae313da 8cf4f72814fc143f 8f7779c6eb9f7fa1 7299aeadb6889018 501d289e4900f7e4 331b99dec4b5433a c7d329eeb6dd2654 5e96e55b874be909"}, 
        {"m": "a"*1000000, "r256": "cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0", "r512": "e718483d0ce76964 4e2e42c7bc15b463 8e1f98b13b204428 5632a803afa973eb de0ff244877ea60a 4cb0432ce577c31b eb009c5c2c49aa2e 4eadb217ad8cc09b"}
    ]
    for tv in tvs[:-1]:  # Remove [:-1] to not skip recursion-killer-size case
        m = tv['m']
        realr = tv['r512'].replace(" ","")
        ncr = sha512(m.encode())
        calcr = (''.join("%02x"%(a) for a in ncr ))
        if realr!=calcr:
            print("FAIL")
            print(realr)
            print(calcr)
            quit()
        else:
            print("PASS")
            # print(realr)
            # print(calcr)

if __name__ == '__main__':
    do_some_tests()
