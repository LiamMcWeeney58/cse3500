import random
import os
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


p = dh.generate_parameters(generator=2, key_size=2048)


alice_private = p.generate_private_key()
alice_public = alice_private.public_key()


print(f"")
print(f"")

bob_private = p.generate_private_key()
bob_public = bob_private.public_key()

print(f"")
print(f"")

alice_shared = alice_private.exchange(bob_public)

bob_shared = bob_private.exchange(alice_public)

print(f"")
print(f"")

assert alice_shared == bob_shared , "Secrets don't match"

hkdf = HKDF(
    algorithm=hashes.SHA256(), length=32, salt=None,
    info=b"Hybrid dh-aes encrypt"
)

aes_key = hkdf.derive(alice_shared)
print("Key exchange successful")

print("Parties have made the same shared secret")