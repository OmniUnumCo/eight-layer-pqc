"""
Unit tests for ML-KEM-1024 (NIST FIPS 203)
Layer 4 & Layer 8
Using kyber-py pure Python implementation
"""

import pytest
from kyber_py.ml_kem import ML_KEM_1024


def test_ml_kem_keypair_generation():
    """Test ML-KEM-1024 keypair generation"""
    ek, dk = ML_KEM_1024.keygen()
    assert len(ek) > 0
    assert len(dk) > 0
    # ML-KEM-1024 encapsulation key is 1568 bytes
    assert len(ek) == 1568
    # ML-KEM-1024 decapsulation key is 3168 bytes
    assert len(dk) == 3168


def test_ml_kem_encapsulation_decapsulation():
    """Test ML-KEM-1024 encapsulation/decapsulation round-trip"""
    ek, dk = ML_KEM_1024.keygen()

    # Encapsulate
    shared_key, ciphertext = ML_KEM_1024.encaps(ek)
    assert len(shared_key) == 32  # 256-bit shared secret
    assert len(ciphertext) > 0

    # Decapsulate
    recovered_key = ML_KEM_1024.decaps(dk, ciphertext)

    # Keys must match
    assert shared_key == recovered_key


def test_ml_kem_ciphertext_size():
    """Test ML-KEM-1024 ciphertext is correct size"""
    ek, dk = ML_KEM_1024.keygen()
    shared_key, ciphertext = ML_KEM_1024.encaps(ek)
    # ML-KEM-1024 ciphertext is 1568 bytes
    assert len(ciphertext) == 1568


def test_ml_kem_different_keys_different_secrets():
    """Test that different keypairs produce different shared secrets"""
    ek1, dk1 = ML_KEM_1024.keygen()
    ek2, dk2 = ML_KEM_1024.keygen()

    key1, ct1 = ML_KEM_1024.encaps(ek1)
    key2, ct2 = ML_KEM_1024.encaps(ek2)

    # Different encapsulation keys should produce different results
    assert key1 != key2
    assert ct1 != ct2


def test_ml_kem_deterministic_decapsulation():
    """Test that decapsulation is deterministic"""
    ek, dk = ML_KEM_1024.keygen()
    shared_key, ciphertext = ML_KEM_1024.encaps(ek)

    # Decapsulate multiple times
    recovered1 = ML_KEM_1024.decaps(dk, ciphertext)
    recovered2 = ML_KEM_1024.decaps(dk, ciphertext)

    assert recovered1 == recovered2 == shared_key


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
