import os
import ecdsa
import hashlib
import base58


def generate_private_key():
    """Generate a random private key."""
    return os.urandom(32).hex()


def private_key_to_wif(private_key):
    """Convert the private key to Wallet Import Format (WIF)."""
    extended_key = "80" + private_key
    first_sha = hashlib.sha256(bytes.fromhex(extended_key)).digest()
    second_sha = hashlib.sha256(first_sha).digest()
    checksum = second_sha[:4]
    wif = base58.b58encode(bytes.fromhex(extended_key) + checksum)
    return wif.decode()


def private_key_to_address(private_key):
    """Convert a private key to a Bitcoin address."""
    # Generate the public key
    private_key_bytes = bytes.fromhex(private_key)
    signing_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    public_key = b"\x04" + verifying_key.to_string()

    # Perform SHA-256 and RIPEMD-160 hashing
    sha256_pubkey = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new("ripemd160")
    ripemd160.update(sha256_pubkey)
    hashed_pubkey = ripemd160.digest()

    # Add network byte and checksum
    network_byte = b"\x00" + hashed_pubkey
    first_sha = hashlib.sha256(network_byte).digest()
    second_sha = hashlib.sha256(first_sha).digest()
    checksum = second_sha[:4]
    address_bytes = network_byte + checksum

    # Encode to Base58
    address = base58.b58encode(address_bytes)
    return address.decode()


def load_btc_addresses(file_path):
    """Load BTC addresses from a file."""
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            return set(line.strip() for line in f)
    return set()


def save_to_won(file_path, address, private_key):
    """Save the matching address and private key to won.txt."""
    with open(file_path, "a") as f:
        f.write(f"Address: {address}\nPrivate Key: {private_key}\n\n")


def main():
    btc_file = "BTC.txt"
    won_file = "won.txt"

    # Load Bitcoin addresses from BTC.txt
    btc_addresses = load_btc_addresses(btc_file)
    print(f"Loaded {len(btc_addresses)} addresses from {btc_file}")

    while True:
        # Generate a private key and corresponding address
        private_key = generate_private_key()
        address = private_key_to_address(private_key)

        print(f"Generated Address: {address}")

        # Check if the address matches any in BTC.txt
        if address in btc_addresses:
            print(f"Match found! Saving to {won_file}")
            save_to_won(won_file, address, private_key)
            break


if __name__ == "__main__":
    main()