import random
import string

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

valid_characters = list(string.ascii_letters + string.digits)


def generate_random(length):
	global valid_characters
	return "".join([random.choice(valid_characters) for _ in range(length)])


client_auth_codes: dict[str: bytes] = {}
client_public_keys: dict[str: RSAPublicKey] = {}

# REPLACE ↓ LATER
with open("public_key.pem", "rb") as key_file:
	client_public_keys["user"] = serialization.load_pem_public_key(
		key_file.read(),
		backend=default_backend()
	)


# REPLACE ↑ Later


def generate_auth(length: int, client_id: str) -> bytes:
	auth_code = generate_random(length).encode()
	encrypted_auth = client_public_keys[client_id].encrypt(
		auth_code,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		))
	client_auth_codes[client_id] = auth_code
	return encrypted_auth


def check_auth(auth_code: bytes, client_id: str):
	return client_id in client_auth_codes and auth_code == client_auth_codes[client_id]
