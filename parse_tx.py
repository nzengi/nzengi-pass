def parse_tx_file(filename):
    """tx.txt dosyasından işlemleri ayırıp düzenli bir şekilde parse eder"""
    transactions = []
    
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()
        
        # İşlemleri ayır (her işlem en az 7 satır)
        current_tx = []
        for line in content.split('\n'):
            line = line.strip()
            if line:  # Boş olmayan satır
                current_tx.append(line)
            elif current_tx:  # Boş satır ve elimizde işlem var
                if len(current_tx) >= 7:  # Geçerli işlem
                    tx = {
                        'txid': current_tx[0],
                        'date': current_tx[1],
                        'from_address': current_tx[2],
                        'from_amount': current_tx[3],
                        'to_address': current_tx[4],
                        'to_amount': current_tx[5],
                        'fee': current_tx[6]
                    }
                    transactions.append(tx)
                current_tx = []
                
        # Son işlemi ekle
        if current_tx and len(current_tx) >= 7:
            tx = {
                'txid': current_tx[0],
                'date': current_tx[1],
                'from_address': current_tx[2],
                'from_amount': current_tx[3],
                'to_address': current_tx[4],
                'to_amount': current_tx[5],
                'fee': current_tx[6]
            }
            transactions.append(tx)
    
    return transactions

def write_transactions(transactions, output_file):
    """İşlemleri düzenli bir formatta dosyaya yazar"""
    with open(output_file, 'w', encoding='utf-8') as f:
        for tx in transactions:
            f.write(f"TXID: {tx['txid']}\n")
            f.write(f"Tarih: {tx['date']}\n")
            f.write(f"Gönderen Adres: {tx['from_address']}\n")
            f.write(f"Gönderilen Miktar: {tx['from_amount']}\n")
            f.write(f"Alıcı Adres: {tx['to_address']}\n")
            f.write(f"Alınan Miktar: {tx['to_amount']}\n")
            f.write(f"İşlem Ücreti: {tx['fee']}\n")
            f.write("-" * 70 + "\n\n")

def main():
    # tx.txt'yi parse et
    transactions = parse_tx_file('tx.txt')
    
    # Sonuçları göster
    print(f"Toplam {len(transactions)} işlem bulundu.")
    
    # İşlemleri transaction.txt'ye yaz
    write_transactions(transactions, 'transaction.txt')
    print(f"\nİşlemler transaction.txt dosyasına yazıldı.")

if __name__ == "__main__":
    main() 