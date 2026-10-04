import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
key = ec.generate_private_key(ec.SECP256R1())
sig = key.sign(data, ec.ECDSA(hashes.SHA256()))
h = hashlib.md5(x)
cipher = "AES-128-GCM"
