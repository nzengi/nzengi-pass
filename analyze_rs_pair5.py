from ecdsa import SECP256k1
import hashlib

def calculate_privkey(r, s, z):
    """Tek bir imzadan private key hesapla - yeni formül"""
    N = SECP256k1.order
    
    # R değerinin başındaki 00'ları kırp
    r_str = hex(r)[2:]  # 0x kısmını kaldır
    if len(r_str) > 64:  # 32 byte'dan uzunsa
        r_str = r_str[-64:]  # Son 32 byte'ı al
    r_trimmed = int(r_str, 16)
    
    # k = (z + r*priv)/s formülünden:
    # priv = (s*k - z)/r mod N
    # k değerlerini dene
    for k in range(1, 1000):
        try:
            r_inv = pow(r_trimmed, -1, N)
            priv = ((s * k - z) * r_inv) % N
            if priv != 0:  # Sıfır olmayan private key'leri göster
                print(f"k={k}: {hex(priv)}")
        except:
            continue

# İşlem 1'deki değerler
r = int("3f9f278ce63649520709f602c2afa3cfd6ea5cf22ca59e83e46d116a8db42537", 16)
s = int("7b0e8a398c606bf01ec4bcd87babd1c8a7293412c1889b716e5c55fdc8369b38", 16)
z = int("6a7f34905fed5de525f065a9b5dc0961d44a8f648e0441dcaa3f1d7af2b0524c", 16)

print("R değerinin başındaki 00'ları kırpılmış formül deniyorum...")
calculate_privkey(r, s, z) 