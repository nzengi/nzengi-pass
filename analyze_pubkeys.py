from ecdsa import SECP256k1
import hashlib
import base58

def pubkey_to_address(pubkey_hex):
    """Public key'den Bitcoin adresi oluştur"""
    sha256_hash = hashlib.sha256(bytes.fromhex(pubkey_hex)).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    version_ripemd160_hash = b'\x00' + ripemd160_hash
    double_sha256 = hashlib.sha256(hashlib.sha256(version_ripemd160_hash).digest()).digest()
    checksum = double_sha256[:4]
    binary_address = version_ripemd160_hash + checksum
    return base58.b58encode(binary_address).decode('utf-8')

# İşlem 3'teki public key'ler
pubkey1 = "02b19c7a477256076ab096e585d29b385c3e534fc40475516b4df72d4279b16338"
pubkey2 = "02ca6e64322b23a4ee612ed9bef8669d37cd421b6987154c1e440f6520c93ffd5c"

print(f"Public Key 1: {pubkey1}")
print(f"Address 1: {pubkey_to_address(pubkey1)}")
print("-" * 50)
print(f"Public Key 2: {pubkey2}")
print(f"Address 2: {pubkey_to_address(pubkey2)}") 