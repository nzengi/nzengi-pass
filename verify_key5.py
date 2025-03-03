from ecdsa import SECP256k1, SigningKey
import hashlib
import base58

def calculate_privkey(r1, s1, z1, r2, s2, z2):
    """İki imzadan private key hesapla - R değerleri kırpılmış"""
    N = SECP256k1.order
    
    # R değerlerini kırp (başındaki 00'ları kaldır)
    r1 = int(r1[2:], 16)  # 00b38de0... -> b38de0...
    r2 = int(r2[2:], 16)  # 00a5067b... -> a5067b...
    
    s_diff = (s2 - s1) % N
    z_diff = (z2 - z1) % N
    k = (z_diff * pow(s_diff, -1, N)) % N
    
    r_inv = pow(r1, -1, N)
    priv = ((s1 * k - z1) * r_inv) % N
    return k, priv

# İşlem 3'teki değerler (R değerleri tam haliyle)
r1 = "00b38de07a0591ed4b9f3362acbbff3215ea47d4a565ba3d46fa7c05c49f12e59d"
s1 = int("45af7a550243b9b7f0975696230a901724aaf5ca9f58e5a50b7c16ccfff031ef", 16)
z1 = int("6a7f34905fed5de525f065a9b5dc0961d44a8f648e0441dcaa3f1d7af2b0524c", 16)

r2 = "00a5067b749e4e873cc68ec3914bce4afe84639f634370af85f6c51c0996ad8f65"
s2 = int("764835ca75d24dc10284ebb193ce2c5436ff4645dd1e7126bb982bc0f8d1c007", 16)
z2 = int("d3a8b1994e26cfb3aa22abc577f98bc25cdcb9a4f2f3960e70b9ed0527db555a", 16)

k, priv = calculate_privkey(r1, s1, z1, r2, s2, z2)
if k and priv:
    print(f"k: {hex(k)}")
    print(f"Private key: {hex(priv)}")
    
    # Private key'i doğrula
    sk = SigningKey.from_secret_exponent(priv, curve=SECP256k1)
    vk = sk.get_verifying_key()
    pubkey = vk.to_string("compressed").hex()
    
    # Adresi hesapla
    sha256_hash = hashlib.sha256(bytes.fromhex(pubkey)).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    version_ripemd160_hash = b'\x00' + ripemd160_hash
    double_sha256 = hashlib.sha256(hashlib.sha256(version_ripemd160_hash).digest()).digest()
    checksum = double_sha256[:4]
    binary_address = version_ripemd160_hash + checksum
    address = base58.b58encode(binary_address).decode('utf-8')
    
    print(f"Address: {address}") 