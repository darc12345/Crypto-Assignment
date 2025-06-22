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
