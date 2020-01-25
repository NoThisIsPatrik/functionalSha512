#!/usr/bin/python3
__author__ = 'Patrik Lundin'
__license__ = 'LGPL3.0'
import struct

sha512 = lambda m:(lambda m,h:(lambda f,*p:f(f,*p))((lambda f,m,h:f(f,m[128:],(lambda h,v,i,w:(lambda f,*p:f(f,*p))(lambda v80,h,v,i,w:v80(v80,h,(lambda T:((T+((v[0]>>28)^(v[0]>>34)^(v[0]>>39)^(v[0]<<25)^(v[0]<<30)^(v[0]<<36))+((v[0]&v[1])^(v[0]&v[2])^(v[1]&v[2])))&((1<<64)-1),v[0],v[1],v[2],(v[3]+T)&((1<<64)-1),v[4],v[5],v[6]))(v[7]+((v[4]>>14)^(v[4]<<50)^(v[4]>>18)^(v[4]<<46)^(v[4]>>41)^(v[4]<<23))+(v[4]&v[5])+((~v[4])&v[6])+(0x428a2f98d728ae22,0x7137449123ef65cd,0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc,0x3956c25bf348b538,0x59f111f1b605d019,0x923f82a4af194f9b,0xab1c5ed5da6d8118,0xd807aa98a3030242,0x12835b0145706fbe,0x243185be4ee4b28c,0x550c7dc3d5ffb4e2,0x72be5d74f27b896f,0x80deb1fe3b1696b1,0x9bdc06a725c71235,0xc19bf174cf692694,0xe49b69c19ef14ad2,0xefbe4786384f25e3,0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65,0x2de92c6f592b0275,0x4a7484aa6ea6e483,0x5cb0a9dcbd41fbd4,0x76f988da831153b5,0x983e5152ee66dfab,0xa831c66d2db43210,0xb00327c898fb213f,0xbf597fc7beef0ee4,0xc6e00bf33da88fc2,0xd5a79147930aa725,0x06ca6351e003826f,0x142929670a0e6e70,0x27b70a8546d22ffc,0x2e1b21385c26c926,0x4d2c6dfc5ac42aed,0x53380d139d95b3df,0x650a73548baf63de,0x766a0abb3c77b2a8,0x81c2c92e47edaee6,0x92722c851482353b,0xa2bfe8a14cf10364,0xa81a664bbc423001,0xc24b8b70d0f89791,0xc76c51a30654be30,0xd192e819d6ef5218,0xd69906245565a910,0xf40e35855771202a,0x106aa07032bbd1b8,0x19a4c116b8d2d0c8,0x1e376c085141ab53,0x2748774cdf8eeb99,0x34b0bcb5e19b48a8,0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb,0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3,0x748f82ee5defb2fc,0x78a5636f43172f60,0x84c87814a1f0ab72,0x8cc702081a6439ec,0x90befffa23631e28,0xa4506cebde82bde9,0xbef9a3f7b2c67915,0xc67178f2e372532b,0xca273eceea26619c,0xd186b8c721c0c207,0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178,0x06f067aa72176fba,0x0a637dc5a2c898a6,0x113f9804bef90dae,0x1b710b35131c471b,0x28db77f523047d84,0x32caab7b40c72493,0x3c9ebe0a15c9bebc,0x431d67c49c100d4c,0x4cc5d4becb3e42b6,0x597f299cfc657e2a,0x5fcb6fab3ad6faec,0x6c44198c4a475817)[i]+w[i]),i+1,w) if i<80 else [(x+y)&((1<<64)-1) for x,y in zip(h,v)],h,v,i,w))(h,h,0,(lambda w:(lambda f,*p:f(f,*p))((lambda f,w:f(f,w+[(w[-16]+w[-7]+((w[-15]>>1)^(w[-15]<<63)^(w[-15]>>8)^(w[-15]<<56)^(w[-15]>>7))+((w[-2]>>19)^(w[-2]<<45)^(w[-2]>>61)^(w[-2]<<3)^(w[-2]>>6)))&((1<<64)-1)])if len(w)<80 else w),w))(list(struct.unpack('!16Q',m[:128])))))if m else struct.pack("!8Q",*h)),m,h))(m+b"\x80"+b"\x00"*((128-16-1)+(128*((len(m)%128)>(128-16-1)))-(len(m)%128))+(b"\x00"*8)+struct.pack("!Q",len(m)*8),(0x6a09e667f3bcc908,0xbb67ae8584caa73b,0x3c6ef372fe94f82b,0xa54ff53a5f1d36f1,0x510e527fade682d1,0x9b05688c2b3e6c1f,0x1f83d9abfb41bd6b,0x5be0cd19137e2179))

def do_some_tests():
    tvs = [
        {"m":"abc", "r256": "ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad", "r512": "ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a 2192992a274fc1a8 36ba3c23a3feebbd 454d4423643ce80e 2a9ac94fa54ca49f"},
        {"m": "", "r256": "e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855", "r512": "cf83e1357eefb8bd f1542850d66d8007 d620e4050b5715dc 83f4a921d36ce9ce 47d0d13c5d85f2b0 ff8318d2877eec2f 63b931bd47417a81 a538327af927da3e"}, 
        {"m": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "r256": "248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1", "r512": "204a8fc6dda82f0a 0ced7beb8e08a416 57c16ef468b228a8 279be331a703c335 96fd15c13b1b07f9 aa1d3bea57789ca0 31ad85c7a71dd703 54ec631238ca3445"}, 
        {"m": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "r256": "cf5b16a7 78af8380 036ce59e 7b049237 0b249b11 e8f07a51 afac4503 7afee9d1", "r512": "8e959b75dae313da 8cf4f72814fc143f 8f7779c6eb9f7fa1 7299aeadb6889018 501d289e4900f7e4 331b99dec4b5433a c7d329eeb6dd2654 5e96e55b874be909"}, 
        {"m": "a"*1000000, "r256": "cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0", "r512": "e718483d0ce76964 4e2e42c7bc15b463 8e1f98b13b204428 5632a803afa973eb de0ff244877ea60a 4cb0432ce577c31b eb009c5c2c49aa2e 4eadb217ad8cc09b"}
    ]
    for tv in tvs[:-1]:  
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
