from KKI import RSA

#define RSA class locally
rsa = RSA()

#generate p and q
print("Generating RSA key pair...")
rsa.innitialize_rsa(e=65537)
public_key = rsa.get_public_key()
private_key = rsa.get_private_key()

print(f"Public Key (n, e): {public_key}")
print(f"Private Key (n, d): {private_key}")

#original plaintext to be encrypted
plaintext = b"Rivest, Shamir, Adleman. RSA!"
print(f"\nPlaintext: {plaintext.decode('utf-8')}")

#encrypt the plaintext with RSA
ciphertext = rsa.encrypt(plaintext)
print(f"Ciphertext: {ciphertext.hex()}")

#decrypt the ciphtertext
decrypted_ciphertext = rsa.decrypt(ciphertext)
print(f"Decrypted Text: {decrypted_ciphertext.decode('utf-8')}")

#save previous RSA state to rsa_keys.json
rsa_keys = "rsa_keys.json"
rsa.save_state(rsa_keys)
print(f"\nRSA keys saved to {rsa_keys}")

#create new RSA instance and load previous state from rsa_keys.json
new_rsa = RSA()
new_rsa.load_state(rsa_keys)
print(f"RSA keys loaded from {rsa_keys}")
print(f"Loaded Public Key: {new_rsa.get_public_key()}")

