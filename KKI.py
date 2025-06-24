import secrets
import datetime
import hashlib
import math
import gmpy2


def long_to_bytes(n: int) -> bytes:
    """Convert a long integer to bytes.
    input: n - a long integer
    output: bytes representation of n"""
    length = (n.bit_length() + 7) // 8 or 1
    return n.to_bytes(length)


def bytes_to_long(b: bytes) -> int:
    """Convert bytes to a long integer.
    input: b - bytes
    output: long integer representation of b"""
    return int.from_bytes(b)


class HashDRBG():
    def __init__(self, seedlen: int):
        """Initialize the Hash DRBG with a given seed length."""
        self.seedlen = seedlen
        self.personalization_string = b'NeverGonnaGiveYouUp'
        self.C: bytes = None
        self.V: bytes = None
        self.reseed_counter = 1
        self.reseed_interval = 5
        self.seed_material = None
        self.seed: bytes = None
        self.outlen = 256

        self.__initialize_state()  # Initial reseed to set up the DRBG
    
    def __generate_nonce(self)-> bytes:
        """Generate a nonce for the DRBG
        input: None
        output: bytes representation of the nonce
        """
        temp = int(datetime.datetime.now(datetime.timezone.utc).timestamp()*1000000)
        return temp.to_bytes(length=(temp.bit_length() // 8) + 1) 
    def __Hash_df(self, m:bytes)-> bytes:
        """Return the result of hashing m with SHA-256. The outleng is 256 bits
        input: m - bytes to be hashed
        output: bytes representation of the hash
        """
        return hashlib.sha256(m).digest()
    def __initialize_state(self):
        """Reseed the DRBG with new entropy
        input: None
        output: None
        """
        entropy_input = secrets.token_bytes(self.seedlen // 8)
        nonce = self.__generate_nonce()
        self.seed_material = entropy_input + nonce + self.personalization_string
        self.seed = self.__Hash_df(self.seed_material)
        self.V = self.seed
        self.C = self.__Hash_df(b'00000000'+ self.V)
        self.reseed_counter = 1

    def __reseed(self, additional_input:bytes = b''):
        """Reseed the DRBG with additional input
        input: additional_input - bytes to be added to the reseed
        output: None
        """
        entropy_input = secrets.token_bytes(self.seedlen // 8)
        if self.V is None or self.C is None or type(self.V) is not bytes or type(self.C) is not bytes:
            raise Exception("DRBG has not been initialized")
        self.seed_material = b"00000001" +self.V+ entropy_input + additional_input
        self.seed = self.__Hash_df(self.seed_material)
        self.V = self.seed
        self.C = self.__Hash_df(b'00000001' + self.V)
        self.reseed_counter = 1
    def leftmost_bits(self, data: bytes, n: int) -> bytes:
        """
        Return the n leftmost bits of 'data', as a bytes object of length ceil(n/8).
        """
        if n < 0:
            raise ValueError("n must be non-negative")
        if n == 0:
            return b''

        total_bits = len(data) * 8
        x = int.from_bytes(data, 'big')
        if n > total_bits:
            raise ValueError(f"n ({n}) is greater than the total bit width of data ({total_bits})")
        # drop (total_bits - n) rightmost bits
        x >>= (total_bits - n)
        out_len = (n + 7) // 8
        return x.to_bytes(out_len, 'big')

    def __hash_gen(self, requested_bits:int) -> bytes:
        """Generate hash output based on the current state
        input: requested_bits - number of bits to be generated
        output: bytes representation of the generated bits"""
        output = b''
        m = math.ceil(requested_bits / self.outlen)
        data = bytes_to_long(self.V)
        for i in range(m):
            w = self.__Hash_df(long_to_bytes(data))
            output = output + w
            data = (data + 1) % 2**self.seedlen
        return self.leftmost_bits(output, requested_bits)
    def generate_ramdom_bits(self, requested_bits:int) -> bytes:
        """Generate random bytes using the DRBG
        input: requested_bits - number of bits to be generated
        output: bytes representation of the generated bits
        """
        if self.reseed_counter >= self.reseed_interval:
            self.__reseed()
        self.reseed_counter += 1
        output = self.__hash_gen(requested_bits)
        H = self.__Hash_df(b"00000003"+ self.V)
        self.V = long_to_bytes(bytes_to_long(self.V + H+long_to_bytes(self.reseed_counter)) % 2**self.seedlen)
        return output
    def generate_random_int(self, min_value:int, max_value:int) -> int:
        """Generate a random integer in the range [min_value, max_value)
        input: min_value - minimum value (inclusive), max_value - maximum value (exclusive)
        output: random integer in the range [min_value, max_value)"""
        if min_value >= max_value:
            raise ValueError("min_value must be less than max_value")
        range_size = max_value - min_value
        if range_size <= 0:
            raise ValueError("Range size must be greater than 0")
        bit_size:int = int(gmpy2.ceil(gmpy2.log2(range_size+1)))
        while True:
            random_bytes = self.generate_ramdom_bits(bit_size)
            random_int = bytes_to_long(random_bytes)
            if random_int < range_size:
                return min_value + random_int
            
import json
class RSA():
    def __init__(self):
        self.p = None
        self.q = None
        self.n = None
        self.e = None
        self.d = None
        self.drbg = HashDRBG(seedlen=256)  
        self.security_strength = 128
        self.nlen = 3072 #This is hardcoded in respect to SP800-57, Part 1 for security_strength 128
        self.min_mr = 4
    def __long_to_bytes(self,n: int) -> bytes:
        """Convert a long integer to bytes.
        input: n - a long integer
        output: bytes representation of n"""
        length = (n.bit_length() + 7) // 8 or 1
        return n.to_bytes(length)
    def __zn_multiplication(self, a:int, b:int, n:int)->int:
        """Calculate a and b in zn field
        input: 
        a   - integer
        b   - integer
        n   - zn
        output:
        (a*b)%n"""
        if a > b:
            smallest:int = b
            biggest:int = a
        else:
            smallest:int = a
            biggest:int = b
        del a, b
        str_big:str = str(bin(biggest))[2:]
        result = list()
        length = len(str_big)
        result = 0
        result += smallest * int(str_big[length-1])
        for i in range(1, length):
            smallest = (smallest << 1) % n
            result = (result + smallest*int(str_big[length-1-i]))%n
        del smallest, biggest
        return result

    def __zn_power(self, a:int, k:int, n:int)->int:
      """"Return the value of a to the power of k in xn"""
      str_k = str(bin(k))[2:][::-1]
      result = 1
      temp = a
      for i in range(len(str_k)):
        if(str_k[i]=='1'):
          result = self.__zn_multiplication(result, temp, n)
        temp = self.__zn_multiplication(temp, temp, n)
      return result % n

    def __bytes_to_long(self, b: bytes) -> int:
        """Convert bytes to a long integer."""
        return int.from_bytes(b)
    def __gcd(self, a, b):
        """Calculate the greatest common divisor (GCD) of two integers a and b."""
        a = abs(a)
        b = abs(b)
        if a==0 and b==0:
            raise ValueError("GCD is undefined for 0 and 0")
        if b == 0: # Added base case for Euclidean algorithm
            return a
        while b:
            a, b = b, a % b
        return a
    def __is_perfect_square(self, c:int)->bool:
        """Check if n is a perfect square
        input: n - an integer
        output: True if n is a perfect square, False otherwise
        """
        n = 0
        while (1<<n) < c:
            n += 1
        m = (n//2)+1 if n%2==1 else (n//2)
        xi = gmpy2.mpq(self.drbg.generate_random_int(2**(m-1), 2**m)) #wrapping it with gmpy2.mpz to avoid float conversion errors
        while True:
            xi = (xi*xi+c)/(2*xi)
            if (xi*xi < ((1<<m)+c)):
                break
        xi = math.floor(xi)
        if c == xi*xi:
            return True #perfect square
        else:
            return False #not a perfect square
    
    
    def __find_k_and_q(self, n:int)->tuple[int, int]:
        """Return a tuple (k, q). The definition is the same as the one in miler-rabin test"""
        temp = int(n)
        s = 0
        while temp % 2 == 0:
            s += 1
            temp = temp >> 1
        return s, temp
    def __jacobi(self, a:int, n:int)->int:
        """subroutine for jacobi symbol calculation"""
        a = a % n
        if a ==1 or n ==1:
            return 1
        if a == 0:  
            return 0    
        e, a1 = self.__find_k_and_q(a)
        if e%2==0:
            s = 1
        elif (n%8) == 1 or (n%8) == 7:
                s = 1
        elif (n%8) == 3 or (n%8) == 5:
            s = -1
        if ((n%4)==3 and a1 % 4 == 3):
            s = -s
        n1 = n % a1
        return self.__jacobi(n1, a1) * s
    def __miller_rabin(self, w:int, k:int)-> bool:
        """p is the prime number that will be tested, while k is the number of rounds
        input: 
        w - the number to be tested, itterations - the number of rounds.
        k - the number of rounds
        """
        a, m = self.__find_k_and_q(w-1)
        for i in range(k):
            b = secrets.randbelow(w-4)+2
            if not (1<b<w-1):
                continue
            z = pow(b, m, w)
            if (z==1 or z==w-1):
                continue
            for j in range(1, a):
                z = pow(z, 2, w)
                if z == w-1:
                    break
                if z == 1:
                    return False
            else:
                return False
        return True #probably prime
    def __lucas_test(self, c:int)-> bool:
        """Lucas test for primality"""
        if self.__is_perfect_square(c):
            return False
        s = 0
        while True:
            s+=1
            if(s%2==1):
                d = s*2+3
            else:
                d = ((s*2+3)*-1)
            jcb = self.__jacobi(d, c)
            if jcb == 0:
                return False #composite
            if(jcb==-1 and self.__gcd(c, (1-d)//4)==1):
                break
        k = c+1
        bin_k = str(bin(k))[2:]
        bin_k = bin_k[::-1] #because according to the pseudo code, it is krkr-1,...k0
        r = len(bin_k)-1 #since we start counting from 0
        u_i = 1
        v_i = 1
        inverse_2 = pow(2, -1, c)
        for i in range(r-1, -1, -1): #since the stop  is exclusive, 0 is turned into -1
            u_temp = (u_i*v_i) % c
            v_temp = ((v_i*v_i + d*u_i*u_i)*inverse_2) % c
            if bin_k[i] == '1':
                u_i = ((u_temp + v_temp)*inverse_2 )% c
                v_i = ((v_temp + d*u_temp)*inverse_2) % c
            else:
                u_i = u_temp
                v_i = v_temp
        #END FOR
        if u_i == 0:
            return True #probably prime
        else:
            return False #composite

    def __get_probable_prime(self, e:int, a:int=None, b:int = None) -> int: #there is a mechanism that generates provable primes, but we opt for probable primes
        """Generate a probable prime number with the given security strength
        Input: 
        e - public exponent
        a,b - elements of {1,3,5,7} if one wants to specify p % 8 == a or p % 8 ==1. 
        """
        if self.nlen < 2048:
            raise ValueError("nlen must be at least 2048 bits")
        if not ((16<math.log2(e)<256) or e % 2 == 1): #checking if e follows the constrains
            raise ValueError("e must be an odd integer between 16 and 256 bits")
        # Generate p
        i = 0 
        while True:
            ub = 2**(self.nlen//2)
            lb = (((2**(self.nlen//2-1)) * int(math.sqrt(2)*1e12)) //int(1e12))
            p = (self.drbg.generate_random_int(lb, ub))
            if a is not None:
                p = p + ((a-p)%8)
            if p % 2 == 0:
               p +=1 
            if p < (((2**(self.nlen//2-1)) * int(math.sqrt(2)*1e12)) //int(1e12)): #to avoid float conversion error 
               continue
            if self.__gcd(p-1, e) == 1:
                if self.__miller_rabin(p, self.min_mr*2):
                    if self.__lucas_test(p):
                        self.p = p
                        break
            i += 1
            if i > self.nlen*5:
                raise Exception("Failed to generate a probable prime after many attempts")
        # Generate q
        i = 0
        while True:
            q  =bytes_to_long(self.drbg.generate_ramdom_bits(self.nlen//2))
            if b is not None:
                q = q + ((b-q)%8)
            if q % 2 == 0:
               q +=1 
            if q < (((2**(self.nlen//2-1)) * int(math.sqrt(2)*1e12)) //int(1e12)):
                continue
            if (abs(p-q)<((2**(self.nlen//2-100)))):
                continue
            if self.__gcd(q-1, e) == 1:
                if self.__miller_rabin(q, self.min_mr*2):
                    if self.__lucas_test(q):
                        self.q = q
                        break
            i += 1
            if i > self.nlen*10:
                raise Exception("Failed to generate a probable prime after many attempts")
    def __extended_euclidian_algorithm(self, a, b):

        # Base case for recursive extended Euclidean algorithm
        if a == 0:
            # gcd(0, b) = b.  The equation is 0*x + b*y = b.  So x=0, y=1.
            return b, 0, 1 

        # Recursive call: modular_inverse(b % a, a)
        # This finds gcd(b % a, a) and coefficients x', y' such that (b % a)x' + ay' = gcd(b % a, a)
        gcd_val, x1_rec, y1_rec = self.__extended_euclidian_algorithm(b % a, a)

        x_rec = y1_rec - (b // a) * x1_rec  # this is x for original 'a' (which is current 'b' in recursive call)
        y_rec = x1_rec                      # this is y for original 'b' (which is current 'a' in recursive call)
                                            # the roles of a and b are swapped in the recursive call's perspective
                                            # relative to the formula ax + by = gcd(a,b)

        return gcd_val, x_rec, y_rec
    def __modular_inverse(self, a, m):
        gcd_val, x, y = self.__extended_euclidian_algorithm(a, m)
        if gcd_val != 1:
            raise ValueError(f"No modular inverse exists for {a} mod {m}")
        return x % m  # x might be negative, so we take it modulo m to get a positive result
    def innitialize_rsa(self, e:int, a:int=None, b:int=None):
        """Initialize RSA with the given public exponent and optional constraints for p and q"""
        if self.p is not None or self.q is not None:
            raise Exception("RSA is already initialized")
        self.__get_probable_prime(e, a, b)
        self.n = self.p * self.q
        phi = (self.p-1)*(self.q-1)
        if self.__gcd(e, phi) != 1:
            raise ValueError("e must be coprime to phi(n)")
        self.e = e
        self.d = self.__modular_inverse(self.e, phi)
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt the plaintext using RSA public key"""
        if self.n is None or self.e is None:
            raise Exception("RSA is not initialized")
        plaintext_int = self.__bytes_to_long(plaintext)
        if plaintext_int >= self.n:
            raise ValueError("Plaintext must be less than n")
        ciphertext_int = self.__zn_power(plaintext_int, self.e, self.n)
        ciphertext = self.__long_to_bytes(ciphertext_int)
        return ciphertext
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt the ciphertext using RSA private key"""
        if self.n is None or self.d is None:
            raise Exception("RSA is not initialized")
        ciphertext_int = self.__bytes_to_long(ciphertext)
        plaintext_int = self.__zn_power(ciphertext_int, self.d, self.n)
        plaintext = self.__long_to_bytes(plaintext_int)
        return plaintext
    def get_public_key(self) -> tuple[int, int]:
        """Return the public key (n, e)"""
        if self.n is None or self.e is None:
            raise Exception("RSA is not initialized")
        return self.n, self.e    
    def get_private_key(self) -> tuple[int, int]:
        """Return the private key (n, d)"""
        if self.n is None or self.d is None:
            raise Exception("RSA is not initialized")
        return self.n, self.d
    def save_state(self, filename: str):
        """Save the RSA state to a .json file"""
        state = {
            'p': (self.p),
            'q': (self.q),
            'n': (self.n),
            'e': self.e,
            'd': (self.d)
        }
        with open(filename, 'w') as f:
            json.dump(state, f)
    def load_state(self, filename: str):
        """Load the RSA state from a file"""
        with open(filename, 'rb') as f:
            state = json.load(f)
            self.p = (state['p'])
            self.q = (state['q'])
            self.n = (state['n'])
            self.e = state['e']
            self.d = (state['d'])
            if not (self.p and self.q and self.n and self.e and self.d):
                raise ValueError("Invalid RSA state in the file")
        
# rsa = RSA()
# rsa.innitialize_rsa(e=65537, a=1, b=3)  # Example initialization with e=65537 and constraints for p and q
# # Example usage
# public_key = rsa.get_public_key()
# private_key = rsa.get_private_key()
# print(f"Public Key: {public_key}")
# print(f"Private Key: {private_key}")
# # Example encryption and decryption
# plaintext = b"Hello, RSA!"
# ciphertext = rsa.encrypt(plaintext)
# print(f"Ciphertext: {ciphertext.hex()}")
# decrypted_text = rsa.decrypt(ciphertext)
# print(f"Decrypted Text: {decrypted_text.decode('utf-8')}")
# # Save and load RSA state
# rsa.save_state('rsa_state.json')
# rsa.load_state('rsa_state.json')