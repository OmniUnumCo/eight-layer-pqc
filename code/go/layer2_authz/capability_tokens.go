package authorization

// Layer 2: Quantum-Resistant Authorization
// RBAC with PQC-signed capability tokens

import (
    "crypto/rand"
    "time"
)

type HybridCapabilityToken struct {
    RoleID        string
    ResourceARN   string
    Expiry        time.Time
    Nonce         [32]byte
    ClassicalMAC  [32]byte
    PQCSignature  []byte
}

// [PASTE FULL IMPLEMENTATION FROM ARCHITECTURE.MD]
