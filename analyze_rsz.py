from ecdsa import SECP256k1

def analyze_signature(r, s, z):
    """R,S,Z değerlerini analiz et"""
    r_int = int(r, 16)
    s_int = int(s, 16)
    z_int = int(z, 16)
    
    # k = (z1 - z2)/(s1 - s2) mod N olabilir
    print(f"R: {r}")
    print(f"S: {s}")
    print(f"Z: {z}")
    print(f"R başlangıç: {r[:8]}")  # İlk 4 byte
    print("-" * 50)

def analyze_signature_pair(sig1, sig2):
    """İki imzayı analiz et ve private key bulmaya çalış"""
    N = SECP256k1.order
    
    r1 = int(sig1['r'], 16)
    s1 = int(sig1['s'], 16)
    z1 = int(sig1['z'], 16)
    
    r2 = int(sig2['r'], 16)
    s2 = int(sig2['s'], 16)
    z2 = int(sig2['z'], 16)
    
    # k = (z1 - z2)/(s1 - s2) mod N formülünü dene
    try:
        s1_minus_s2 = (s1 - s2) % N
        s1_minus_s2_inv = pow(s1_minus_s2, -1, N)
        z1_minus_z2 = (z1 - z2) % N
        
        k = (z1_minus_z2 * s1_minus_s2_inv) % N
        
        # Private key = (s*k - z)/r mod N
        r_inv = pow(r1, -1, N)
        priv = ((s1 * k - z1) * r_inv) % N
        
        print(f"Muhtemel k: {hex(k)}")
        print(f"Muhtemel private key: {hex(priv)}")
    except:
        print("Private key hesaplanamadı")

# İşlem 3'teki imzaları analiz et
signatures = [
    {
        'r': "00b38de07a0591ed4b9f3362acbbff3215ea47d4a565ba3d46fa7c05c49f12e59d",
        's': "45af7a550243b9b7f0975696230a901724aaf5ca9f58e5a50b7c16ccfff031ef",
        'z': "6a7f34905fed5de525f065a9b5dc0961d44a8f648e0441dcaa3f1d7af2b0524c"
    },
    {
        'r': "00a5067b749e4e873cc68ec3914bce4afe84639f634370af85f6c51c0996ad8f65",
        's': "764835ca75d24dc10284ebb193ce2c5436ff4645dd1e7126bb982bc0f8d1c007",
        'z': "d3a8b1994e26cfb3aa22abc577f98bc25cdcb9a4f2f3960e70b9ed0527db555a"
    }
]

print("İşlem 3'teki imza çiftini analiz ediyorum...")
analyze_signature_pair(signatures[0], signatures[1]) 