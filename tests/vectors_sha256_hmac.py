# generate_correct_vectors.py
import hashlib

# Test 1: password="password", salt="salt", iterations=2, dklen=20
result1 = hashlib.pbkdf2_hmac('sha256', b'password', b'salt', 2, 20)
print(f"Test 1 (2 iterations): {result1.hex()}")

# Test 2: password="password", salt="salt", iterations=4096, dklen=20
result2 = hashlib.pbkdf2_hmac('sha256', b'password', b'salt', 4096, 20)
print(f"Test 2 (4096 iterations): {result2.hex()}")

# Test 3
password3 = b'passwordPASSWORDpassword'
salt3 = b'saltSALTsaltSALTsaltSALTsaltSALTsalt'
result3 = hashlib.pbkdf2_hmac('sha256', password3, salt3, 4096, 25)
print(f"Test 3 (complex): {result3.hex()}")