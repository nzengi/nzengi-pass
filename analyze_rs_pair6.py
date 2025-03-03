from ecdsa import SECP256k1
import hashlib

def analyze_r_values(r1, r2):
    """İki R değerini karşılaştır"""
    N = SECP256k1.order
    
    # R değerlerinin farkını al
    r_diff = (r1 - r2) % N
    print(f"R1: {hex(r1)}")
    print(f"R2: {hex(r2)}")
    print(f"Fark: {hex(r_diff)}")
    
    # Farkın son byte'ını kontrol et
    last_byte = r_diff & 0xFF
    print(f"Son byte: {hex(last_byte)}")

# İşlem 1 ve 2'deki R değerleri
r1 = int("3f9f278ce63649520709f602c2afa3cfd6ea5cf22ca59e83e46d116a8db42537", 16)
r2 = int("0c71cd4959141d2874514f6a3ea504a326ec751f8e3eab80609900bb1311263b", 16)

print("R değerlerini analiz ediyorum...")
analyze_r_values(r1, r2) 