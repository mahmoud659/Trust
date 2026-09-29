from services.manifest_service import ManifestService
from services.signature_service import SignatureService


# Manifest وصل لنا
manifest = {
    "claim_id": "CLM-001",
    "capture_id": "CAP-001",
    "image_hash": "ABC123"
}


# نحول الـ Manifest إلى bytes ثابتة
manifest_bytes = ManifestService.canonicalize(
    manifest
)


# في التجربة فقط:
# نعمل Private Key + Public Key
private_key, public_key = SignatureService.generate_keys()


# نعمل Signature
signature = SignatureService.sign(
    manifest_bytes,
    private_key
)


print("\nSignature:")
print(signature)


# Verify قبل التعديل
result = SignatureService.verify(
    manifest_bytes,
    signature,
    public_key
)


print("\nBefore Modification:")
print("Signature Valid:", result)


print("\n------------------------")
input("اضغط Enter علشان نعدل الـ Manifest...")
print("------------------------")


# نعدل البيانات
manifest["claim_id"] = "CLM-999"


# نحول الـ Manifest المعدلة إلى bytes
modified_manifest_bytes = ManifestService.canonicalize(
    manifest
)


# نحاول Verify بنفس الـ Signature القديمة
result = SignatureService.verify(
    modified_manifest_bytes,
    signature,
    public_key
)


print("\nAfter Modification:")
print("Signature Valid:", result)