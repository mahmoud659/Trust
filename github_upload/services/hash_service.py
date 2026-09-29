import hashlib


class HashService:

    @staticmethod
    def calculate(file_path: str) -> str:
        with open(file_path, "rb") as file:
            data = file.read()

        return hashlib.sha256(data).hexdigest()


    @staticmethod
    def verify(
        file_path: str,
        expected_hash: str,
    ) -> bool:

        current_hash = HashService.calculate(file_path)

        return current_hash == expected_hash