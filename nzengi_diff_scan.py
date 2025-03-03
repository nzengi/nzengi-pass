# -*- coding: utf-8 -*-
"""
@author: iceland
"""
import sys
import json
from urllib.request import urlopen
from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point
import hashlib
from collections import Counter

# SECP256k1 sabitleri
G = SECP256k1.generator
N = SECP256k1.order
ZERO = Point(None, None, None)  # infinity point

def read_txids_from_transactions(filename):
    """transaction.txt'den TXID'leri okur"""
    txids = []
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            if line.startswith('TXID:'):
                txid = line.split('TXID:')[1].strip()
                txids.append(txid)
    return txids

def get_rawtx_from_blockchain(txid):
    """Blockchain'den raw transaction alır"""
    try:
        htmlfile = urlopen(f"https://blockchain.info/rawtx/{txid}?format=hex", timeout = 20)
        return htmlfile.read().decode('utf-8')
    except:
        print(f'Unable to fetch RawTx for {txid}')
        return None

def get_rs(sig):
    """İmzadan r,s değerlerini çıkarır"""
    rlen = int(sig[2:4], 16)
    r = sig[4:4+rlen*2]
    s = sig[8+rlen*2:]
    return r, s

def split_sig_pieces(script):
    """Script'ten imza parçalarını ayırır"""
    sigLen = int(script[2:4], 16)
    sig = script[2+2:2+sigLen*2]
    r, s = get_rs(sig[4:])
    pubLen = int(script[4+sigLen*2:4+sigLen*2+2], 16)
    pub = script[4+sigLen*2+2:]
    assert(len(pub) == pubLen*2)
    return r, s, pub

def parseTx(txn):
    """Raw transaction'ı parse eder"""
    if len(txn) < 130:
        print('[WARNING] rawtx most likely incorrect')
        return None
        
    inp_list = []
    inp_nu = int(txn[8:10], 16)
    first = txn[0:10]
    cur = 10
    
    for m in range(inp_nu):
        prv_out = txn[cur:cur+64]
        var0 = txn[cur+64:cur+64+8]
        cur = cur+64+8
        scriptLen = int(txn[cur:cur+2], 16)
        script = txn[cur:2+cur+2*scriptLen]
        r, s, pub = split_sig_pieces(script)
        seq = txn[2+cur+2*scriptLen:10+cur+2*scriptLen]
        inp_list.append([prv_out, var0, r, s, pub, seq])
        cur = 10+cur+2*scriptLen
    rest = txn[cur:]
    return [first, inp_list, rest]

def getSignableTxn(parsed):
    """İmzalanabilir transaction oluşturur"""
    res = []
    first, inp_list, rest = parsed
    tot = len(inp_list)
    for one in range(tot):
        e = first
        for i in range(tot):
            e += inp_list[i][0]
            e += inp_list[i][1]
            if one == i:
                e += '1976a914' + HASH160(inp_list[one][4]) + '88ac'
            else:
                e += '00'
            e += inp_list[i][5]
        e += rest + "01000000"
        z = hashlib.sha256(hashlib.sha256(bytes.fromhex(e)).digest()).hexdigest()
        res.append([inp_list[one][2], inp_list[one][3], z, inp_list[one][4], e])
    return res

def HASH160(pubk_hex):
    """HASH160 hesaplar"""
    pub_bytes = bytes.fromhex(pubk_hex)
    sha256_hash = hashlib.sha256(pub_bytes).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    return ripemd160_hash.hex()

def analyze_signatures(transactions):
    """İmzaları analiz eder"""
    print("\n=== İmza Analizi Başlıyor ===")
    
    target_address = "14dJRoKyj2i83uRbTUeKqhFMwvFZcpiXyn"
    target_pubkey = "02aef80b855bac84033414d15c70082b541e4923c174bfdf01ff9a4e48ae05a553"
    
    # İşlemleri grupla
    rsz_values = []
    seen_txids = set()  # Tekrar eden işlemleri önlemek için
    
    for tx in transactions:
        if tx['txid'] not in seen_txids and tx['R'] and tx['S'] and tx['Z']:
            rsz_values.append({
                'txid': tx['txid'],
                'R': int(tx['R'], 16),
                'S': int(tx['S'], 16),
                'Z': int(tx['Z'], 16)
            })
            seen_txids.add(tx['txid'])
    
    print(f"\nToplam {len(rsz_values)} benzersiz işlem analiz ediliyor...")
    
    # 1. Duplicate R Kontrolü
    r_values = {}  # R değerlerini ve TXID'lerini sakla
    for tx in rsz_values:
        r_hex = hex(tx['R'])[2:]
        if r_hex in r_values:
            print("\n!!! Duplicate R değeri bulundu !!!")
            print(f"R: {r_hex}")
            print(f"TX1: {r_values[r_hex]}")
            print(f"TX2: {tx['txid']}")
            
            # İlgili işlemlerin değerlerini bul
            tx1 = next(t for t in rsz_values if t['txid'] == r_values[r_hex])
            tx2 = tx
            
            # Private key hesapla
            try:
                k = (tx1['Z'] - tx2['Z']) * inv(tx1['S'] - tx2['S'], N) % N
                priv = (tx1['S'] * k - tx1['Z']) * inv(tx1['R'], N) % N
                print(f"Hesaplanan private key: {hex(priv)}")
                
                # Private key doğrulama
                pubkey_point = scalar_multiplication(priv)
                if pubkey_point == pubkey_to_point(target_pubkey):
                    print("!!! Private key doğrulandı !!!")
            except:
                print("Private key hesaplanamadı")
        else:
            r_values[r_hex] = tx['txid']
    
    # 2. R Değerleri Arasındaki İlişkileri Kontrol Et
    print("\nR değerleri arasındaki ilişkiler kontrol ediliyor...")
    for i in range(len(rsz_values)):
        for j in range(i+1, len(rsz_values)):  # Sadece farklı işlemleri karşılaştır
            r1 = rsz_values[i]['R']
            r2 = rsz_values[j]['R']
            
            # R değerleri arasındaki farkı kontrol et
            diff = abs((r1 - r2) % N)  # Mutlak farkı al
            if 0 < diff < 1000000:  # 0'dan büyük ve küçük farkları kontrol et
                print(f"\nİlginç R farkı bulundu!")
                print(f"TX1: {rsz_values[i]['txid']}")
                print(f"TX2: {rsz_values[j]['txid']}")
                print(f"Fark: {diff}")

def inv(a, n):
    """Modüler çarpımsal ters hesaplar"""
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    gcd, x, y = extended_gcd(a, n)
    if gcd != 1:
        raise Exception('Modüler çarpımsal ters bulunamadı')
    return x % n

def scalar_multiplication(k):
    """Scalar multiplication with generator point"""
    return G * k

def pubkey_to_point(pubkey_hex):
    """Convert public key hex to point"""
    if len(pubkey_hex) == 66:  # compressed
        prefix = int(pubkey_hex[0:2], 16)
        x = int(pubkey_hex[2:], 16)
        curve = SECP256k1.curve
        y_squared = (pow(x, 3, curve.p()) + 7) % curve.p()
        y = pow(y_squared, (curve.p() + 1) // 4, curve.p())
        if prefix == 2 and y % 2 == 0:
            y_final = y
        elif prefix == 3 and y % 2 == 1:
            y_final = y
        else:
            y_final = curve.p() - y
        return Point(curve, x, y_final)
    return None

def main():
    print("İşlemler transaction.txt'den okunuyor...")
    txids = read_txids_from_transactions('transaction.txt')
    print(f"Toplam {len(txids)} işlem bulundu.")
    
    transactions = []
    for txid in txids:
        try:
            rawtx = get_rawtx_from_blockchain(txid)
            if rawtx:
                m = parseTx(rawtx)
                if m:
                    e = getSignableTxn(m)
                    tx = {
                        'txid': txid,
                        'R': e[0][0],
                        'S': e[0][1],
                        'Z': e[0][2],
                        'pubkey': e[0][3]
                    }
                    transactions.append(tx)
                    print(f"\nİşlem alındı: {txid}")
                    print(f"R: {tx['R']}")
                    print(f"S: {tx['S']}")
                    print(f"Z: {tx['Z']}")
        except Exception as e:
            print(f"Hata - {txid}: {str(e)}")
            continue
    
    # İmza analizi
    analyze_signatures(transactions)

if __name__ == "__main__":
    main()
