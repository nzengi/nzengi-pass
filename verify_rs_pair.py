from ecdsa import SigningKey, SECP256k1
import hashlib
import base58

def verify_privkey(priv_int):
    """Private key'i doğrula"""
    try:
        # Private key'den public key oluştur
        sk = SigningKey.from_secret_exponent(priv_int, curve=SECP256k1)
        vk = sk.get_verifying_key()
        
        # Hem compressed hem uncompressed public key'i dene
        pubkey_comp = vk.to_string("compressed").hex()
        pubkey_uncomp = vk.to_string("uncompressed").hex()
        
        # Public key'lerden adres oluştur
        addr_comp = pubkey_to_address(pubkey_comp)
        addr_uncomp = pubkey_to_address(pubkey_uncomp)
        
        print(f"\nPrivate Key: {hex(priv_int)}")
        print(f"Compressed Address: {addr_comp}")
        print(f"Uncompressed Address: {addr_uncomp}")
        return True
    except:
        return False

def pubkey_to_address(pubkey_hex):
    """Public key'den Bitcoin adresi oluştur"""
    sha256_hash = hashlib.sha256(bytes.fromhex(pubkey_hex)).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    version_ripemd160_hash = b'\x00' + ripemd160_hash
    double_sha256 = hashlib.sha256(hashlib.sha256(version_ripemd160_hash).digest()).digest()
    checksum = double_sha256[:4]
    binary_address = version_ripemd160_hash + checksum
    return base58.b58encode(binary_address).decode('utf-8')

# Bulunan private key'leri doğrula
private_keys = [
    0xcf9ca8582257ea56f7377ea1365fd99783f921086924a5f9f82ae92e8a6ea059,
    0xb247a002a51f1744d734b275091b2a3375b14eac75940e0ac426631b8b84d6e9,
    0x94f297ad27e64432b731e648dbd67acf67697c508203761b9021dd088c9b0d79,
    0x779d8f57aaad7120972f1a1cae91cb6b5921a9f48e72de2c5c1d56f58db14409,
    0x5a4887022d749e0e772c4df0814d1c074ad9d7989ae2463d2818d0e28ec77a99
]

print("Private key'leri doğruluyorum...")
for priv in private_keys:
    verify_privkey(priv) 