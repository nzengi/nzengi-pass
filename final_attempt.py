from ecdsa import SECP256k1
import hashlib
import base58

def try_all_variants(r1, s1, z1, r2, s2, z2):
    """R değerlerinin farklı varyasyonlarını dene"""
    N = SECP256k1.order
    
    # R değerlerinin varyasyonları
    r1_variants = [
        int(r1, 16),                    # Tam hali
        int(r1[2:], 16),               # 00 kırpılmış
        int(r1[:-2], 16),              # Son byte kırpılmış
        int(r1[2:-2], 16)              # Hem 00 hem son byte kırpılmış
    ]
    
    r2_variants = [
        int(r2, 16),
        int(r2[2:], 16),
        int(r2[:-2], 16),
        int(r2[2:-2], 16)
    ]
    
    for r1_val in r1_variants:
        for r2_val in r2_variants:
            try:
                s_diff = (s2 - s1) % N
                z_diff = (z2 - z1) % N
                k = (z_diff * pow(s_diff, -1, N)) % N
                priv = ((s1 * k - z1) * pow(r1_val, -1, N)) % N
                print(f"R1: {hex(r1_val)}")
                print(f"R2: {hex(r2_val)}")
                print(f"k: {hex(k)}")
                print(f"Private key: {hex(priv)}")
                print("-" * 50)
            except:
                continue

# İşlem 3'teki değerler
r1 = "00b38de07a0591ed4b9f3362acbbff3215ea47d4a565ba3d46fa7c05c49f12e59d"
s1 = int("45af7a550243b9b7f0975696230a901724aaf5ca9f58e5a50b7c16ccfff031ef", 16)
z1 = int("6a7f34905fed5de525f065a9b5dc0961d44a8f648e0441dcaa3f1d7af2b0524c", 16)

r2 = "00a5067b749e4e873cc68ec3914bce4afe84639f634370af85f6c51c0996ad8f65"
s2 = int("764835ca75d24dc10284ebb193ce2c5436ff4645dd1e7126bb982bc0f8d1c007", 16)
z2 = int("d3a8b1994e26cfb3aa22abc577f98bc25cdcb9a4f2f3960e70b9ed0527db555a", 16)

print("Tüm varyasyonları deniyorum...")
try_all_variants(r1, s1, z1, r2, s2, z2) 