import os

txids = [
    "d5de907c6f81d381efe91328d876c96114257a1afe3e8dbdb45080c6a3fe8e76",
    "6ab4e1d53715ad4dfef74eb61f8ebefda3d3cdd0ce1bcc426974648953003e4a",
    "1e148dd196b6ba10a313b57ec144a5a53122217e24fcf7d5aeb51e8bb5d0c43d"
]

for txid in txids:
    print(f"\nAnalyzing transaction: {txid}")
    os.system(f"python3 nzengi_pass.py -txid {txid}") 