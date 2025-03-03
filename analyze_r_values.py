def analyze_r_pairs(r1, r2):
    """İki R değeri arasındaki ilişkiyi analiz et"""
    r1_int = int(r1, 16)
    r2_int = int(r2, 16)
    diff = abs(r1_int - r2_int)
    
    print(f"R1: {r1}")
    print(f"R2: {r2}")
    print(f"Fark: {diff}")
    print(f"Fark (hex): {hex(diff)}")
    print("-" * 50)

# Tüm işlemlerdeki R değerleri
r_values = [
    "3f9f278ce63649520709f602c2afa3cfd6ea5cf22ca59e83e46d116a8db42537",  # İşlem 1
    "0c71cd4959141d2874514f6a3ea504a326ec751f8e3eab80609900bb1311263b",  # İşlem 2
    "00b38de07a0591ed4b9f3362acbbff3215ea47d4a565ba3d46fa7c05c49f12e59d",  # İşlem 3-1
    "00a5067b749e4e873cc68ec3914bce4afe84639f634370af85f6c51c0996ad8f65"   # İşlem 3-2
]

print("Tüm R değerleri arasındaki farkları analiz ediyorum...")
for i in range(len(r_values)):
    for j in range(i+1, len(r_values)):
        print(f"\nR{i+1} ve R{j+1} karşılaştırması:")
        analyze_r_pairs(r_values[i], r_values[j]) 