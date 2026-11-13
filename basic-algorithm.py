import random
import os
import warnings
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning) # gets rid of warning statement regarding removing
# diffie hellman keyexchange from cryptography

print("=" * 50)
print("       DIFFIE-HELLMAN EPHEMERAL (DHE) KEY EXCHANGE")
print("=" * 50)

print("\n[Step 1] Generating 2048-bit DHE parameters (p, g)... (Might take a while)")
p = dh.generate_parameters(generator=2, key_size=2048)
print("    -> Parameters found, moving on.")

print("\n[Step 2] Generating Public & Private Keys for Users involved...")
alice_private = p.generate_private_key()
alice_public = alice_private.public_key()

bob_private = p.generate_private_key()
bob_public = bob_private.public_key()

alice_pub_bytes = alice_public.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
) # this variable is the actual public key, which we give metadata to signify that it is

bob_pub_bytes = bob_public.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)

print(f"    Last 32 bits of Alice Public Key ({len(alice_pub_bytes)}B): ...{alice_pub_bytes.hex()[-32:]}")
print(f"    Last 32 bits of Bob Public Key   ({len(bob_pub_bytes)}B): ...{bob_pub_bytes.hex()[-32:]}")

print("\n[Step 3] Exchanging Public Keys & Computing Shared Secrets...")
alice_shared = alice_private.exchange(bob_public)

bob_shared = bob_private.exchange(alice_public)

print(f"Alice Shared Secret: {alice_shared.hex()[:40]}...")
print(f"Bob Shared Secret:   {bob_shared.hex()[:40]}...")

assert alice_shared == bob_shared , "Secrets don't match"
print("    Shared secrets match! \n")


print("\n[Step 4] Deriving 256-bit AES Key via HKDF-SHA256...")
hkdf = HKDF(
    algorithm=hashes.SHA256(), length=32, salt=None,
    info=b"Hybrid dh-aes encrypt"
)

aes_key = hkdf.derive(alice_shared)

print("Key exchange successful \n")
print(f"    Derived AES-256 Key: {aes_key.hex()} \n")
print("Parties have made the same shared secret")
