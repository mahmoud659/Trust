import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


class SignatureService:

    @staticmethod
    def generate_keys():

        private_key = ec.generate_private_key(
            ec.SECP256R1()
        )

        public_key = private_key.public_key()

        return private_key, public_key


    @staticmethod
    def sign(
        data: bytes,
        private_key,
    ) -> str:

        signature = private_key.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )

        return base64.b64encode(
            signature
        ).decode("utf-8")


    @staticmethod
    def verify(
        data: bytes,
        signature: str,
        public_key,
    ) -> bool:

        try:

            signature_bytes = base64.b64decode(
                signature
            )

            public_key.verify(
                signature_bytes,
                data,
                ec.ECDSA(hashes.SHA256())
            )

            return True

        except InvalidSignature:

            return False