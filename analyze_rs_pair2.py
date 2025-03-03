from ecdsa import SECP256k1
import hashlib

def calculate_privkey(r, s, z):
    """Tek bir imzadan private key hesapla - alternatif formül"""
    N = SECP256k1.order
    
    # k = z/s mod N formülünü dene
    try:
        s_inv = pow(s, -1, N)
        k = (z * s_inv) % N
        r_inv = pow(r, -1, N)
        priv = ((s * k - z) * r_inv) % N
        print(f"k: {hex(k)}")
        print(f"Private key: {hex(priv)}")
    except:
        print("Private key hesaplanamadı")

# İşlem 1'deki değerler
r = int("3f9f278ce63649520709f602c2afa3cfd6ea5cf22ca59e83e46d116a8db42537", 16)
s = int("7b0e8a398c606bf01ec4bcd87babd1c8a7293412c1889b716e5c55fdc8369b38", 16)
z = int("6a7f34905fed5de525f065a9b5dc0961d44a8f648e0441dcaa3f1d7af2b0524c", 16)

print("Alternatif formül deniyorum...")
calculate_privkey(r, s, z) 