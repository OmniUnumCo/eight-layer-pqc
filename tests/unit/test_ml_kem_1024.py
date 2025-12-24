"""
Unit tests for ML-KEM-1024 (NIST FIPS 203)
Layer 4 & Layer 8
"""

import pytest
from pqcrypto.kem.kyber1024 import generate_keypair, encrypt, decrypt

def test_ml_kem_keypair_generation():
    """Test ML-KEM-1024 keypair generation"""
    public_key, secret_key = generate_keypair()
    assert len(public_key) > 0
    assert len(secret_key) > 0
    print("✅ ML-KEM-1024 keypair generation successful")

def test_ml_kem_encapsulation_decapsulation():
    """Test ML-KEM-1024 encaps/decaps round-trip"""
    public_key, secret_key = generate_keypair()
    
    # Encapsulate
    ciphertext, shared_secret_sender = encrypt(public_key)
    
    # Decapsulate
    shared_secret_receiver = decrypt(ciphertext, secret_key)
    
    # Verify shared secrets match
    assert shared_secret_sender == shared_secret_receiver
    assert len(shared_secret_sender) == 32  # 256 bits
    print("✅ ML-KEM-1024 encaps/decaps verified")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
