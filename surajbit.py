import hashlib
from bitcoinaddress import Wallet

# Function to generate a SHA-256 hash
def sha256_hash(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def generate_hashes(input_string: str, output_file: str, count: int):
    """Generate 'count' SHA-256 hashes and save to output_file."""
    with open(output_file, "w") as file:
        current_hash = input_string
        for _ in range(count):
            current_hash = sha256_hash(current_hash)
            file.write(current_hash + "\n")

def generate_wallets(input_file: str, output_file: str):
    """Generate wallet information from hashes in input_file and save to output_file."""
    with open(input_file, "r") as file:
        private_keys = file.readlines()

    with open(output_file, "a") as output_file:
        for key in private_keys:
            key = key.strip()  # Remove any extra whitespace
            wallet = Wallet(key)
            output_file.write(str(wallet) + "\n")
            print(wallet)

def main():
    input_string = "initialstring"  # Initial input string for hashing
    hash_file = "suraj.txt"
    wallet_file = "suraj1.txt"
    
    while True:
        # Step 1: Generate 100,000 hashes and write to suraj.txt
        generate_hashes(input_string, hash_file, 100000)

        # Step 2: Generate wallet information for each hash and append to suraj1.txt
        generate_wallets(hash_file, wallet_file)

        # Step 3: Clear the contents of suraj.txt
        open(hash_file, "w").close()

if __name__ == "__main__":
    main()
