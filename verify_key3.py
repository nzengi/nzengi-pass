from ecdsa import SigningKey, SECP256k1
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
    address = base58.b58encode(binary_address).decode('utf-8')
    return address

# Yeni bulunan private key
private_key = 0x70c3203633149dd6ea29d2f37fa5775240db4428334d3bfdbc0a97c6457dd7f2

# Private key'den public key oluştur
sk = SigningKey.from_secret_exponent(private_key, curve=SECP256k1)
vk = sk.get_verifying_key()

# Hem compressed hem uncompressed public key'i dene
pubkey_comp = vk.to_string("compressed").hex()
pubkey_uncomp = vk.to_string("uncompressed").hex()

# Her iki public key'den adres oluştur
address_comp = pubkey_to_address(pubkey_comp)
address_uncomp = pubkey_to_address(pubkey_uncomp)

print(f"Private Key: {hex(private_key)}")
print(f"Compressed Address: {address_comp}")
print(f"Uncompressed Address: {address_uncomp}") 