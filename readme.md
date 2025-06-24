# README.md

## RSA Cryptography Project

This repository contains an implementation of the RSA public-key cryptosystem. The project was developed as part of a cryptography class, focusing on foundational number theoretic operations, secure prime generation, and the core RSA encryption/decryption functionalities.

### Features

* **Modular Arithmetic**: Efficient implementations of modular multiplication and modular exponentiation.
* **Probabilistic Primality Testing**: Includes the Miller-Rabin primality test.
* **Deterministic Primality Testing**: Includes the Lucas primality test for higher confidence in prime generation.
* **Cryptographically Secure Random Number Generation**: Utilizes a Hash-based Deterministic Random Bit Generator (HashDRBG) compliant with NIST SP 800-90A.
* **RSA Key Generation**: Generates RSA key pairs with support for custom public exponents and adherence to NIST recommendations for prime number selection (e.g., bit length, proximity of primes, specific congruences).
* **RSA Encryption and Decryption**: Implements standard RSA encryption and decryption operations.
* **Key Management**: Functionality to save and load RSA key pairs to/from a JSON file.

### Project Structure

* `KKI.ipynb`: Jupyter Notebook containing all the Python code for the RSA implementation, along with detailed comments and explanations for each function.
* `project_documentation.pdf`: A comprehensive LaTeX-generated PDF document detailing the project, including:
    * Introduction to RSA.
    * Explanation of each core function with pseudocode and code snippets.
    * Design choices and their cryptographic rationale, citing NIST and PKCS standards.
    * Example usage.
    * References and Glossary.
* `images/`: Directory containing figures and pseudocode diagrams used in the documentation.
* `README.md`: This file.

### Setup and Installation

This project requires Python 3 and the `gmpy2` library for efficient arbitrary-precision arithmetic and built-in primality testing for comparison/validation.

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/darc12345/Crypto-Assignment.git
    cd Crypto-Assignment
    ```

2.  **Create a virtual environment (recommended)**:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: `venv\Scripts\activate`
    ```

3.  **Install dependencies**:
    ```bash
    pip3 install gmpy2
    ```
    *Note: Installing `gmpy2` might require C compiler tools. Please refer to the [gmpy2 documentation](https://gmpy2.readthedocs.io/en/latest/install.html) for specific platform requirements.*

### Usage as a Python Module

The `KKI.py` file can be imported as a module into other Python projects to make use of the RSA functionalities.

**Example `RSA_test.py`:**

```python
from KKI import RSA

if __name__ == "__main__":
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

```

