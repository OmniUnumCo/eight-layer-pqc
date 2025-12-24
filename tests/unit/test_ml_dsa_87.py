"""
Unit tests for ML-DSA-87 (NIST FIPS 204)
All layers using signatures
Using dilithium-py pure Python implementation
"""

import pytest
from dilithium_py.ml_dsa import ML_DSA_87


def test_ml_dsa_keypair_generation():
    """Test ML-DSA-87 keypair generation"""
    pk, sk = ML_DSA_87.keygen()
    assert len(pk) > 0
    assert len(sk) > 0
    # ML-DSA-87 public key is 2592 bytes
    assert len(pk) == 2592
    # ML-DSA-87 secret key is 4896 bytes
    assert len(sk) == 4896


def test_ml_dsa_sign_verify():
    """Test ML-DSA-87 sign/verify round-trip"""
    pk, sk = ML_DSA_87.keygen()
    message = b"Eight-Layer Quantum-Hardened Architecture v2.0"

    # Sign
    signature = ML_DSA_87.sign(sk, message)
    assert len(signature) > 0
    # ML-DSA-87 signature is 4627 bytes
    assert len(signature) == 4627

    # Verify
    is_valid = ML_DSA_87.verify(pk, message, signature)
    assert is_valid is True


def test_ml_dsa_tamper_detection():
    """Test ML-DSA-87 detects message tampering"""
    pk, sk = ML_DSA_87.keygen()
    message = b"Original message"
    tampered = b"Tampered message"

    signature = ML_DSA_87.sign(sk, message)

    # Should fail on tampered message
    is_valid = ML_DSA_87.verify(pk, tampered, signature)
    assert is_valid is False


def test_ml_dsa_signature_uniqueness():
    """Test that signatures are unique per message"""
    pk, sk = ML_DSA_87.keygen()
    msg1 = b"Message 1"
    msg2 = b"Message 2"

    sig1 = ML_DSA_87.sign(sk, msg1)
    sig2 = ML_DSA_87.sign(sk, msg2)

    # Different messages should produce different signatures
    assert sig1 != sig2


def test_ml_dsa_wrong_key_fails():
    """Test that verification fails with wrong public key"""
    pk1, sk1 = ML_DSA_87.keygen()
    pk2, sk2 = ML_DSA_87.keygen()
    message = b"Test message"

    # Sign with sk1
    signature = ML_DSA_87.sign(sk1, message)

    # Verify with pk1 should succeed
    assert ML_DSA_87.verify(pk1, message, signature) is True

    # Verify with pk2 should fail
    assert ML_DSA_87.verify(pk2, message, signature) is False


def test_ml_dsa_empty_message():
    """Test signing and verifying empty message"""
    pk, sk = ML_DSA_87.keygen()
    message = b""

    signature = ML_DSA_87.sign(sk, message)
    is_valid = ML_DSA_87.verify(pk, message, signature)
    assert is_valid is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
