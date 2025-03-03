from ecdsa import SECP256k1

def calculate_privkey(r1, s1, z1, r2, s2, z2):
    """İki imzadan private key hesapla - alternatif formül"""
    N = SECP256k1.order
    
    # r1 ve r2 aynı olmalı
    if r1 != r2:
        rdiff = (r1 - r2) % N
        print(f"R farkı: {hex(rdiff)}")
    
    # k = (z1*s2 - z2*s1)/(r1*s2 - r2*s1) mod N
    try:
        numerator = (z1 * s2 - z2 * s1) % N
        denominator = (r1 * s2 - r2 * s1) % N
        k = (numerator * pow(denominator, -1, N)) % N
        
        # Private key = (s1*k - z1)/r1 mod N
        priv = ((s1 * k - z1) * pow(r1, -1, N)) % N
        return priv
    except:
        return None

# İşlem 3'teki değerler
r1 = int("00b38de07a0591ed4b9f3362acbbff3215ea47d4a565ba3d46fa7c05c49f12e59d", 16)
s1 = int("45af7a550243b9b7f0975696230a901724aaf5ca9f58e5a50b7c16ccfff031ef", 16)
z1 = int("6a7f34905fed5de525f065a9b5dc0961d44a8f648e0441dcaa3f1d7af2b0524c", 16)

r2 = int("00a5067b749e4e873cc68ec3914bce4afe84639f634370af85f6c51c0996ad8f65", 16)
s2 = int("764835ca75d24dc10284ebb193ce2c5436ff4645dd1e7126bb982bc0f8d1c007", 16)
z2 = int("d3a8b1994e26cfb3aa22abc577f98bc25cdcb9a4f2f3960e70b9ed0527db555a", 16)

priv = calculate_privkey(r1, s1, z1, r2, s2, z2)
if priv:
    print(f"Yeni private key: {hex(priv)}") 