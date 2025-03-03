def decode_tx(hex_tx):
    """Raw transaction'ı parçala"""
    # Version (4 bytes)
    version = hex_tx[:8]
    
    # Input count (var_int)
    pos = 8
    
    # Input
    prev_tx = hex_tx[pos:pos+64]
    pos += 64
    prev_index = hex_tx[pos:pos+8]
    pos += 8
    
    # Script length (6a = 106 bytes)
    script_len = 106
    
    # Signature script
    sig_script = hex_tx[pos:pos+script_len*2]
    pos += script_len*2
    
    print(f"Version: {version}")
    print(f"Previous TX: {prev_tx}")
    print(f"Previous Index: {prev_index}")
    print(f"Script Length: {script_len}")
    print(f"Signature Script: {sig_script}")
    print("-" * 50)
    
    # DER signature'ı parçala
    der_start = sig_script.find("30")
    if der_start >= 0:
        der_len = int(sig_script[der_start+2:der_start+4], 16)
        der_sig = sig_script[der_start:der_start+4+der_len*2]
        
        # R değeri
        r_start = der_start + 6
        r_len = int(sig_script[r_start:r_start+2], 16)
        r_val = sig_script[r_start+2:r_start+2+r_len*2]
        
        # S değeri
        s_start = r_start + 2 + r_len*2 + 2
        s_len = int(sig_script[s_start:s_start+2], 16)
        s_val = sig_script[s_start+2:s_start+2+s_len*2]
        
        print(f"R: {r_val}")
        print(f"S: {s_val}")

# Raw transaction
tx = "0200000001e0b2ae58cf28760975e1e088ad2475f04d16abb0967f3de5a4acbec8dd0e76c5020000006a47304402203f9f278ce63649520709f602c2afa3cfd6ea5cf22ca59e83e46d116a8db4253702207b0e8a398c606bf01ec4bcd87babd1c8a7293412c1889b716e5c55fdc8369b380121034d53163932c9b93942c4361f2f0ff3b3aadb2e50806d32f4ff9f709e86fc6456fdffffff0300000000000000003a6a385765276c6c2062757920796f757220426974636f696e732e2073656c6c2e6275792e626974636f696e4070726f746f6e6d61696c2e636f6d22020000000000001976a9145291b21e2a0ac74ddc57de77ec1d1cbc4dc1603488ac1aaf2e00000000001976a91472e6844820795902150bc0f56c5efc4fe5667edf88ac00000000"

decode_tx(tx) 