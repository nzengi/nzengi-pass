def analyze_r_value(r):
    """R değerinin byte yapısını analiz et"""
    # Başındaki sıfırları say
    leading_zeros = len(r) - len(r.lstrip('0'))
    
    # Son byte'ı kontrol et
    last_byte = r[-2:]  # Son 2 hex karakter = 1 byte
    
    # Uzunluğu kontrol et
    expected_len = 64  # Normal R değeri 32 byte = 64 hex
    actual_len = len(r)
    
    print(f"R değeri: {r}")
    print(f"Başındaki sıfır sayısı: {leading_zeros}")
    print(f"Son byte: 0x{last_byte}")
    print(f"Beklenen uzunluk: {expected_len}")
    print(f"Gerçek uzunluk: {actual_len}")
    print("-" * 50)

# İşlem 3'teki R değerleri
r1 = "00b38de07a0591ed4b9f3362acbbff3215ea47d4a565ba3d46fa7c05c49f12e59d"
r2 = "00a5067b749e4e873cc68ec3914bce4afe84639f634370af85f6c51c0996ad8f65"

print("R1 analizi:")
analyze_r_value(r1)

print("\nR2 analizi:")
analyze_r_value(r2) 