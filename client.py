from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from server import generate_auth, check_auth

with open("private_key.pem", "rb") as key_file:
	private_key = serialization.load_pem_private_key(
		key_file.read(),
		password=None,
		backend=default_backend()
	)

auth_code = generate_auth(length=128, client_id="user")

decrypted = private_key.decrypt(
	auth_code,
	padding.OAEP(
		mgf=padding.MGF1(algorithm=hashes.SHA256()),
		algorithm=hashes.SHA256(),
		label=None
	)
)

print(check_auth(decrypted, "user"))
