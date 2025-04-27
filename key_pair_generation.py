import rsa

def generate_and_save_keys():
    """Generate kunci RSA dan simpan ke dalam bentuk file"""
    try:
        # Generate RSA key pair (2048 bits)
        public_key, private_key = rsa.generate_keypair(2048)
        
        # Ubah keys ke dalam bentuk hexadecimal
        public_key_hex = rsa.convert_to_hex(public_key)
        private_key_hex = rsa.convert_to_hex(private_key)
        
        # Simpan keys ke dalam file
        rsa.save_to_file(public_key_hex, "public_key.txt")
        rsa.save_to_file(private_key_hex, "private_key.txt")
        
        print("\nRSA Key Pair Generation Successful!")
        print("Public Key saved to: public_key.txt")
        print("Private Key saved to: private_key.txt")
        
    except Exception as e:
        print(f"Error generating key pair: {e}")

def main():
    generate_and_save_keys()

if __name__ == "__main__":
    main()