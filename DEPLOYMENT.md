# Deployment Guide

## Eight-Layer Post-Quantum Cryptography Security Framework

This guide covers deploying the Eight-Layer PQC framework in production environments.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Layer Deployment](#layer-deployment)
5. [Integration Patterns](#integration-patterns)
6. [Monitoring](#monitoring)
7. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16+ GB |
| Storage | 20 GB SSD | 100 GB NVMe |
| Network | 1 Gbps | 10 Gbps |

### Software Dependencies

**Python (Layers 1, 4, 6, 7, 8)**
```bash
python >= 3.10
pip install pycryptodome kyber-py dilithium-py
```

**Go (Layer 2 - Authorization)**
```bash
go >= 1.22
```

**Rust (Layer 3 - Network Security)**
```bash
rustc >= 1.75
cargo build --release
```

---

## Installation

### From PyPI (Python Components)

```bash
pip install eight-layer-pqc
```

### From Source

```bash
git clone https://github.com/anumethod/eight-layer-pqc.git
cd eight-layer-pqc

# Install Python dependencies
pip install -r requirements.txt

# Build Go components
cd code/go && go build -v ./...

# Build Rust components
cd code/rust && cargo build --release
```

### Docker Deployment

```dockerfile
FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    golang-go \
    rustc \
    cargo

WORKDIR /app
COPY . .

RUN pip install -r requirements.txt
RUN cd code/go && go build -v ./...
RUN cd code/rust && cargo build --release

CMD ["python", "-m", "eight_layer_pqc"]
```

---

## Configuration

### Environment Variables

```bash
# Layer 1: Identity
export PQC_IDENTITY_KEY_PATH=/etc/pqc/identity.key
export PQC_FIDO2_TIMEOUT=30000

# Layer 2: Authorization
export PQC_AUTHZ_TOKEN_TTL=3600
export PQC_AUTHZ_MAX_SESSIONS=10000

# Layer 3: Network Security
export PQC_NETWORK_SESSION_TIMEOUT=86400
export PQC_NETWORK_MAX_SESSIONS=1000

# Layer 4: Encryption
export PQC_ENCRYPTION_KEY_ROTATION=86400

# Layer 6: PHI Isolation
export PQC_PHI_COMPARTMENT_SIZE=1048576
export PQC_PHI_AUDIT_LEVEL=full

# Layer 7: Self-Healing
export PQC_SELFHEAL_ANOMALY_THRESHOLD=0.85
export PQC_SELFHEAL_CHECK_INTERVAL=60

# Layer 8: Orchestration
export PQC_ORCHESTRATOR_LOG_LEVEL=INFO
```

### Configuration File

Create `/etc/pqc/config.yaml`:

```yaml
layers:
  identity:
    enabled: true
    ml_dsa_level: 87
    fido2_timeout_ms: 30000

  authorization:
    enabled: true
    token_ttl_seconds: 3600
    max_sessions: 10000

  network:
    enabled: true
    hybrid_kex: true
    session_timeout: 86400

  encryption:
    enabled: true
    algorithm: ML-KEM-1024
    key_rotation_hours: 24

  data_classification:
    enabled: true
    default_level: confidential

  phi_isolation:
    enabled: true
    audit_all_access: true

  self_healing:
    enabled: true
    anomaly_threshold: 0.85

  orchestration:
    enabled: true
    log_level: INFO
```

---

## Layer Deployment

### Layer 1: Identity Verification

```python
from code.python.layer1_identity import IdentityManager

# Initialize with ML-DSA-87 keypair
identity_mgr = IdentityManager()

# Register user identity
user_id = identity_mgr.register_identity(
    username="alice",
    public_key=alice_public_key,
    fido2_credential=fido2_cred
)

# Verify identity
verified = identity_mgr.verify_identity(user_id, challenge_response)
```

### Layer 2: Authorization (Go)

```go
package main

import (
    "github.com/TradeMomentumLLC/eight-layer-pqc/layer2_authz"
)

func main() {
    // Initialize authorization manager
    authMgr := layer2_authz.NewAuthorizationManager()

    // Add roles
    authMgr.AddRole("admin", []string{"read", "write", "delete"})
    authMgr.AddRole("user", []string{"read"})

    // Generate capability token
    token, err := authMgr.GenerateToken("user123", "admin", 3600)

    // Validate token
    valid, claims := authMgr.ValidateToken(token)
}
```

### Layer 3: Network Security (Rust)

```rust
use eight_layer_pqc::{SecureServer, SecureClient};

// Server setup
let mut server = SecureServer::default();
let mlkem_pub = server.get_mlkem_public_key();

// Client connection
let client = SecureClient::new(client_id);
let result = client.connect(&x25519_pub, &mlkem_pub)?;

// Server accepts
let conn = server.accept_connection(
    x25519_keypair,
    &result.x25519_public,
    &result.mlkem_ciphertext,
    client_id
)?;
```

### Layer 4: Data Encryption

```python
from code.python.layer4_encryption import HybridEncryption

# Initialize hybrid encryption (AES-256-GCM + ML-KEM-1024)
encryptor = HybridEncryption()

# Encrypt data
ciphertext, metadata = encryptor.encrypt(
    plaintext=sensitive_data,
    associated_data=b"context"
)

# Decrypt data
plaintext = encryptor.decrypt(ciphertext, metadata)
```

### Layer 6: PHI Isolation

```python
from code.python.layer6_phi import PHIManager

# Initialize PHI manager
phi_mgr = PHIManager()

# Create compartment
compartment_id = phi_mgr.create_compartment(
    patient_id="P12345",
    data_classification="PHI"
)

# Store PHI
phi_mgr.store_phi(compartment_id, phi_data, accessor="dr_smith")

# Retrieve with audit
data = phi_mgr.retrieve_phi(compartment_id, accessor="dr_smith")
```

### Layer 7: Self-Healing

```python
from code.python.layer7_selfhealing import SelfHealingOrchestrator

# Initialize orchestrator
orchestrator = SelfHealingOrchestrator()

# Register components
orchestrator.register_component("auth_service", health_check_fn)
orchestrator.register_component("encryption_service", health_check_fn)

# Start monitoring
orchestrator.start_monitoring(interval_seconds=60)

# Handle anomalies automatically
orchestrator.on_anomaly(lambda c, a: orchestrator.heal(c))
```

### Layer 8: Central Orchestration

```python
from code.python.layer8_orchestrator import PQCOrchestrator

# Initialize central orchestrator
orchestrator = PQCOrchestrator()

# Register all layers
orchestrator.register_layer(1, identity_mgr)
orchestrator.register_layer(4, encryptor)
orchestrator.register_layer(6, phi_mgr)
orchestrator.register_layer(7, self_healing)

# Start coordinated operations
orchestrator.start()
```

---

## Integration Patterns

### Microservices Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    API Gateway                               │
│                  (Layer 1: Identity)                         │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────┐
│                 Service Mesh                                 │
│            (Layer 3: Network Security)                       │
│         (X25519 + ML-KEM-1024 Hybrid KEX)                   │
└─────────────────────┬───────────────────────────────────────┘
                      │
    ┌─────────────────┼─────────────────┐
    │                 │                 │
┌───┴───┐        ┌────┴───┐        ┌────┴───┐
│Service│        │Service │        │Service │
│   A   │        │   B    │        │   C    │
│(L2,L4)│        │(L2,L4) │        │(L6,L7) │
└───────┘        └────────┘        └────────┘
```

### Database Integration

```python
# PostgreSQL with Layer 4 encryption
from code.python.layer4_encryption import FieldEncryption

encryptor = FieldEncryption()

# Encrypt sensitive fields before storage
encrypted_ssn = encryptor.encrypt_field(ssn)
cursor.execute(
    "INSERT INTO users (name, ssn_encrypted) VALUES (%s, %s)",
    (name, encrypted_ssn)
)
```

---

## Monitoring

### Health Endpoints

```python
# Add to your Flask/FastAPI app
@app.get("/health/pqc")
def pqc_health():
    return {
        "layer1_identity": identity_mgr.health(),
        "layer2_authz": authz_mgr.health(),
        "layer3_network": network_mgr.health(),
        "layer4_encryption": encryptor.health(),
        "layer6_phi": phi_mgr.health(),
        "layer7_selfhealing": self_healing.health(),
        "layer8_orchestrator": orchestrator.health()
    }
```

### Prometheus Metrics

```python
from prometheus_client import Counter, Histogram

pqc_operations = Counter(
    'pqc_operations_total',
    'Total PQC operations',
    ['layer', 'operation', 'status']
)

pqc_latency = Histogram(
    'pqc_operation_latency_seconds',
    'PQC operation latency',
    ['layer', 'operation']
)
```

### Logging

```python
import logging

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# Each layer logs to its own logger
logger = logging.getLogger('pqc.layer4')
logger.info('Encryption operation completed', extra={
    'algorithm': 'ML-KEM-1024',
    'key_id': key_id,
    'duration_ms': duration
})
```

---

## Troubleshooting

### Common Issues

#### ML-KEM Key Generation Slow

```python
# Use hardware RNG if available
import os
os.environ['PQC_USE_HARDWARE_RNG'] = '1'
```

#### Session Timeout Errors

Check Layer 3 session configuration:
```bash
export PQC_NETWORK_SESSION_TIMEOUT=86400  # 24 hours
```

#### Memory Usage High

Tune self-healing parameters:
```python
orchestrator.set_memory_limit(1024 * 1024 * 512)  # 512MB
orchestrator.set_gc_interval(300)  # 5 minutes
```

### Debug Mode

```bash
export PQC_DEBUG=1
export PQC_LOG_LEVEL=DEBUG
python -m eight_layer_pqc --debug
```

### Validation

Run compliance validation:
```bash
python scripts/validation/validate_nist_compliance.py
```

Expected output:
```
======================================================================
NIST Post-Quantum Cryptography Compliance Validation
======================================================================
ML-KEM-1024 (FIPS 203): COMPLIANT
ML-DSA-87 (FIPS 204): COMPLIANT
AES-256-GCM: COMPLIANT
======================================================================
ALL TESTS PASSED - NIST COMPLIANT
```

---

## Security Considerations

1. **Key Storage**: Store private keys in HSM or secure enclave
2. **Key Rotation**: Rotate ML-KEM keys every 24 hours minimum
3. **Audit Logging**: Enable full audit logging for PHI access
4. **Network Isolation**: Deploy Layer 3 at network perimeter
5. **Monitoring**: Alert on anomaly detection from Layer 7

---

## Support

- Documentation: https://github.com/anumethod/eight-layer-pqc
- Issues: https://github.com/anumethod/eight-layer-pqc/issues
- Security: See SECURITY.md for vulnerability reporting
