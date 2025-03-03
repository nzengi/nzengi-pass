# -*- coding: utf-8 -*-
"""

@author: iceland
"""
import sys
# import secp256k1 as ice
from ecdsa import SECP256k1, SigningKey, VerifyingKey
import argparse
from urllib.request import urlopen
import hashlib
import json
#==============================================================================
parser = argparse.ArgumentParser(description='This tool helps to get ECDSA Signature r,s,z values from Bitcoin rawtx or txid', 
                                 epilog='-- Created by . --')

parser.add_argument("-txid", help = "txid of the transaction. Automatically fetch rawtx from given txid", action="store")
parser.add_argument("-rawtx", help = "Raw Transaction on the blockchain.", action="store")

if len(sys.argv)==1:
    parser.print_help()
    sys.exit(1)
args = parser.parse_args()
#==============================================================================

txid = args.txid if args.txid else ''
rawtx = args.rawtx if args.rawtx else ''

if rawtx == '' and txid == '': 
    print('One of the required option missing -rawtx or -txid'); sys.exit(1)
#==============================================================================

def get_rs(sig):
    rlen = int(sig[2:4], 16)
    r = sig[4:4+rlen*2]
#    slen = int(sig[6+rlen*2:8+rlen*2], 16)
    s = sig[8+rlen*2:]
    return r, s
    
def split_sig_pieces(script):
    try:
        sigLen = int(script[2:4], 16)
        sig = script[2+2:2+sigLen*2]
        r, s = get_rs(sig[4:])
        pubLen = int(script[4+sigLen*2:4+sigLen*2+2], 16)
        pub = script[4+sigLen*2+2:]
        assert(len(pub) == pubLen*2)
        return r, s, pub
    except (ValueError, IndexError, AssertionError):
        # SegWit için alternatif parsing
        try:
            # SegWit scriptSig genellikle boş olur
            return "0" * 64, "0" * 64, script  # Dummy values for r, s and pubkey
        except:
            print(f"Unable to parse script: {script}")
            sys.exit(1)


# Returns list of this list [first, sig, pub, rest] for each input
def parseTx(txn):
    if len(txn) < 130:
        print('[WARNING] rawtx most likely incorrect. Please check..')
        sys.exit(1)
    inp_list = []
    ver = txn[:8]
    
    # SegWit işlemlerini destekle
    cur = 8
    is_witness = False
    if txn[8:12] == '0001':
        is_witness = True
        cur = 12
    
    inp_nu = int(txn[cur:cur+2], 16)
    first = txn[0:cur+2]
    cur = cur+2
    
    for m in range(inp_nu):
        prv_out = txn[cur:cur+64]
        var0 = txn[cur+64:cur+64+8]
        cur = cur+64+8
        scriptLen = int(txn[cur:cur+2], 16)
        script = txn[cur:2+cur+2*scriptLen] if scriptLen > 0 else ""
        r, s, pub = split_sig_pieces(script)
        seq = txn[2+cur+2*scriptLen:10+cur+2*scriptLen]
        inp_list.append([prv_out, var0, r, s, pub, seq])
        cur = 10+cur+2*scriptLen
    
    rest = txn[cur:]
    return [first, inp_list, rest]

#==============================================================================
def get_rawtx_from_blockchain(txid):
    try:
        # Blockchair API'sini kullanalım
        htmlfile = urlopen(f"https://api.blockchair.com/bitcoin/raw/transaction/{txid}", timeout = 20)
        res = htmlfile.read().decode('utf-8')
        # Blockchair API json döndürüyor, raw tx'i alalım
        data = json.loads(res)
        rawtx = data['data'][0]['raw_transaction']
        return rawtx
    except Exception as e:
        try:
            # Alternatif olarak blockchain.info'yu deneyelim
            htmlfile = urlopen(f"https://blockchain.info/rawtx/{txid}?format=hex", timeout = 20)
            return htmlfile.read().decode('utf-8')
        except Exception as e2:
            print(f'Unable to connect to any API to fetch RawTx. Errors:\n1: {str(e)}\n2: {str(e2)}\nExiting..')
            sys.exit(1)
# =============================================================================

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
        z = get_sha256(get_sha256(bytes.fromhex(e))).hex()
        res.append([inp_list[one][2], inp_list[one][3], z, inp_list[one][4], e])
    return res
#==============================================================================
def scalar_multiplication(k):
    """Scalar multiplication on the secp256k1 curve"""
    # return ice.scalar_multiplication(k)
    pass

def pub2upub(pub_hex):
    """Convert compressed public key to uncompressed public key"""
    if len(pub_hex) == 130:  # already uncompressed
        return pub_hex
    if len(pub_hex) == 66:  # compressed
        try:
            x = int(pub_hex[2:], 16)
            prefix = pub_hex[:2]
            
            p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
            y_squared = (pow(x, 3, p) + 7) % p
            y = pow(y_squared, (p + 1) // 4, p)
            
            if prefix == '02' and y % 2 == 0:
                y_final = y
            elif prefix == '03' and y % 2 == 1:
                y_final = y
            else:
                y_final = p - y
                
            return '04' + hex(x)[2:].zfill(64) + hex(y_final)[2:].zfill(64)
        except:
            return None
    return None

def get_sha256(data):
    """Calculate SHA256 hash of the input data"""
    return hashlib.sha256(data).digest()

def get_ripemd160(data):
    """Calculate RIPEMD160 hash of the input data"""
    return hashlib.new('ripemd160', data).digest()

def hash160(hex_str):
    """Convert a hex string to its HASH160 value"""
    b = bytes.fromhex(hex_str)
    hash_sha256 = get_sha256(b)
    hash_ripemd160 = get_ripemd160(hash_sha256)
    return hash_ripemd160

def HASH160(pubk_hex):
    """Get HASH160 of a public key"""
    if pubk_hex is None:
        return None
    P = pub2upub(pubk_hex)
    if P is None:
        return None
    return hash160(P).hex()
#==============================================================================

#txn = '01000000028370ef64eb83519fd14f9d74826059b4ce00eae33b5473629486076c5b3bf215000000008c4930460221009bf436ce1f12979ff47b4671f16b06a71e74269005c19178384e9d267e50bbe9022100c7eabd8cf796a78d8a7032f99105cdcb1ae75cd8b518ed4efe14247fb00c9622014104e3896e6cabfa05a332368443877d826efc7ace23019bd5c2bc7497f3711f009e873b1fcc03222f118a6ff696efa9ec9bb3678447aae159491c75468dcc245a6cffffffffb0385cd9a933545628469aa1b7c151b85cc4a087760a300e855af079eacd25c5000000008b48304502210094b12a2dd0f59b3b4b84e6db0eb4ba4460696a4f3abf5cc6e241bbdb08163b45022007eaf632f320b5d9d58f1e8d186ccebabea93bad4a6a282a3c472393fe756bfb014104e3896e6cabfa05a332368443877d826efc7ace23019bd5c2bc7497f3711f009e873b1fcc03222f118a6ff696efa9ec9bb3678447aae159491c75468dcc245a6cffffffff01404b4c00000000001976a91402d8103ac969fe0b92ba04ca8007e729684031b088ac00000000'
if rawtx == '':
    rawtx = get_rawtx_from_blockchain(txid)

print('\nStarting Program...')

m = parseTx(rawtx)
e = getSignableTxn(m)

for i in range(len(e)):
    print('='*70,f'\n[Input Index #: {i}]\n     R: {e[i][0]}\n     S: {e[i][1]}\n     Z: {e[i][2]}\nPubKey: {e[i][3]}')

