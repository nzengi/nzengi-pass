from ecdsa import SigningKey, SECP256k1
import hashlib
import base58

def pubkey_to_address(pubkey_hex):
    """Public key'den Bitcoin adresi oluştur"""
    # SHA256
    sha256_hash = hashlib.sha256(bytes.fromhex(pubkey_hex)).digest()
    
    # RIPEMD160
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    
    # Version byte ekle (0x00 = mainnet)
    version_ripemd160_hash = b'\x00' + ripemd160_hash
    
    # Double SHA256
    double_sha256 = hashlib.sha256(hashlib.sha256(version_ripemd160_hash).digest()).digest()
    
    # Checksum
    checksum = double_sha256[:4]
    
    # Final binary
    binary_address = version_ripemd160_hash + checksum
    
    # Base58 encode
    address = base58.b58encode(binary_address).decode('utf-8')
    return address

# Bulunan private key
private_key = 0x70ade866ce75ccb58c2029025d2853ebd5f204d5cf3f56df07c5e97d975be2cb

# Private key'den public key oluştur
sk = SigningKey.from_secret_exponent(private_key, curve=SECP256k1)
vk = sk.get_verifying_key()
pubkey = vk.to_string("compressed").hex()

# Public key'den adres oluştur
address = pubkey_to_address(pubkey)

print(f"Private Key: {hex(private_key)}")
print(f"Public Key: {pubkey}")
print(f"Address: {address}") 