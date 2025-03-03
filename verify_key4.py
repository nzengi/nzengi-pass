from ecdsa import SECP256k1
import hashlib
import base58

def calculate_privkey(r1, s1, z1, r2, s2, z2):
    """İki imzadan private key hesapla - son formül"""
    N = SECP256k1.order
    
    # k = (z2 - z1)/(s2 - s1) mod N
    try:
        s_diff = (s2 - s1) % N
        z_diff = (z2 - z1) % N
        k = (z_diff * pow(s_diff, -1, N)) % N
        
        # Private key = (s1*k - z1)/r1 mod N
        r_inv = pow(r1, -1, N)
        priv = ((s1 * k - z1) * r_inv) % N
        return k, priv
    except:
        return None, None

def pubkey_to_address(pubkey_hex):
    """Public key'den Bitcoin adresi oluştur"""
    sha256_hash = hashlib.sha256(bytes.fromhex(pubkey_hex)).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    version_ripemd160_hash = b'\x00' + ripemd160_hash
    double_sha256 = hashlib.sha256(hashlib.sha256(version_ripemd160_hash).digest()).digest()
    checksum = double_sha256[:4]
    binary_address = version_ripemd160_hash + checksum
    address = base58.b58encode(binary_address).decode('utf-8')
    return address

# İşlem 3'teki değerler
r1 = int("00b38de07a0591ed4b9f3362acbbff3215ea47d4a565ba3d46fa7c05c49f12e59d", 16)
s1 = int("45af7a550243b9b7f0975696230a901724aaf5ca9f58e5a50b7c16ccfff031ef", 16)
z1 = int("6a7f34905fed5de525f065a9b5dc0961d44a8f648e0441dcaa3f1d7af2b0524c", 16)

r2 = int("00a5067b749e4e873cc68ec3914bce4afe84639f634370af85f6c51c0996ad8f65", 16)
s2 = int("764835ca75d24dc10284ebb193ce2c5436ff4645dd1e7126bb982bc0f8d1c007", 16)
z2 = int("d3a8b1994e26cfb3aa22abc577f98bc25cdcb9a4f2f3960e70b9ed0527db555a", 16)

k, priv = calculate_privkey(r1, s1, z1, r2, s2, z2)
if k and priv:
    print(f"k: {hex(k)}")
    print(f"Private key: {hex(priv)}") 