import json


class ManifestService:

    REQUIRED_FIELDS = [
        "claim_id",
        "capture_id",
        "image_hash",
    ]

    @staticmethod
    def validate(manifest: dict) -> bool:

        for field in ManifestService.REQUIRED_FIELDS:
            if field not in manifest:
                return False

        return True


    @staticmethod
    def canonicalize(manifest: dict) -> bytes:

        manifest_string = json.dumps(
            manifest,
            sort_keys=True,
            separators=(",", ":"),
        )

        return manifest_string.encode("utf-8")