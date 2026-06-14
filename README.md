# Formal Verification of a V2X Privacy-Preserving Protocol

Formal verification of a privacy-preserving pseudonymous communication protocol for **V2X (Vehicle-to-Everything)** networks using **ProVerif**. The protocol is based on group signatures with pseudonym certificates, enrollment certificates, and a revocation mechanism.

## Overview

This project models a V2X protocol where vehicles obtain **enrollment certificates** from a Certificate Authority (CA) and then register to obtain **group signing keys (gsk)** from a Road-Side Unit (RSU). With a group key, a vehicle can generate **pseudonym certificates** and broadcast signed messages anonymously. A revocation mechanism allows reporting malicious vehicles and updating the group master secret key.

The formal analysis covers:

- **Sanity checks**: correctness of registration, key distribution, and revocation
- **Authentication**: mutual authentication between CA and vehicles
- **Secrecy**: vehicle identity (`vid`) confidentiality under different key-compromise scenarios
- **Temporal properties**: ordering of revocation events and message delivery
- **Unlinkability**: observational equivalence — a vehicle sending multiple messages is indistinguishable from one sending a single message
- **Offline guessing attacks**: strong secrecy of `vid` and encrypted messages

## Requirements

- [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/) (>= 2.00)

Install it on Ubuntu/Debian:

```bash
sudo apt install proverif
```

Or build from source at [https://github.com/blanchet/proverif](https://github.com/blanchet/proverif).

## Structure

```
.
├── leakage_cask/                          # CA Secret Key leakage analysis
│   ├── group_signatures_phases.pv         #   Base model (cask leaked)
│   ├── leakage-cask.pv                    #   Extended model (RSU naming)
│   └── traces q*/                         #   Variants with individual queries enabled
├── leakage_gmsk/                          # Group Master Secret Key leakage analysis
│   ├── group_signatures_phases.pv         #   Base model (gmsk leaked)
│   ├── query_attacker(vid)_phase_0/       #   Secrecy in phase 0
│   ├── query_attacker(vid)_phase_1/       #   Secrecy in phase 1
│   ├── query_attacker(vid)_phase_2/       #   Secrecy in phase 2
│   ├── query_attacker(vid)_ONLY1VEHICLE/  #   Single vehicle scenario
│   ├── query_attacker(vid)_MoreVehicles/  #   Multiple vehicles scenario
│   ├── query attacker PFS/                #   Perfect Forward Secrecy
│   └── traces q*/                         #   Variants with individual queries enabled
├── offline_attacks/                       # Offline guessing attack analysis
│   └── offline-attacks.pv                 #   weaksecret queries
├── unlinkability/                         # Unlinkability (observational equivalence)
│   ├── 0_pre/                             #   Preliminary version (replicated vehicles)
│   │   ├── group_signatures_phases_unlinkability.pv
│   │   └── trace*.pdf / trace*.dot        #   Attack traces
│   └── 1_post/                            #   Refined versions
│       ├── traces1_without_nonce/         #    2 vehicles, no nonce, no revocation
│       ├── traces2_with_nonce_and_revocation_part/  #  Full model with nonce + revocation
│       └── traces3_with_nonce_without_revocation_part/ #  Nonce, no revocation
├── sources/                               # Reference papers and resources
│   ├── manual.pdf                         #   ProVerif manual
│   ├── Pseudonym_Schemes_in_Vehicular_Networks.pdf
│   ├── Efficient and robust pseudonymous authentication.pdf
│   └── Formal Verification of a v2x privacy preserving scheme.pdf
└── Report_formal_verification_of_a_V2X_protocol.pdf  # Full thesis/report
```

## How to Run

Run ProVerif on any `.pv` file:

```bash
proverif leakage_cask/group_signatures_phases.pv
```

The base models (`leakage_cask/group_signatures_phases.pv` and `leakage_gmsk/group_signatures_phases.pv`) contain all queries as comments. To test a specific query, uncomment it in the file, or use the pre-configured variants under the `traces q*/` directories.

### Examples by category

```bash
# CA Secret Key leakage (Q3 — weak secrecy)
proverif leakage_cask/traces\ q3/leakage-cask.pv

# Group Master Secret Key leakage (all queries)
proverif leakage_gmsk/group_signatures_phases.pv

# Attacker vid query — phase 0
proverif leakage_gmsk/query_attacker\(vid\)_phase_0/trace1.pv

# Offline guessing attack
proverif offline_attacks/offline-attacks.pv

# Unlinkability — full model (nonce + revocation)
proverif unlinkability/1_post/traces2_with_nonce_and_revocation_part/group_signatures_phases_unlinkability_v2.pv
```

## Protocol Model

The formal model in ProVerif includes the following cryptographic primitives:

| Primitive | Description |
|-----------|-------------|
| `cert(vid, vpk, cask)` | Enrollment certificate binding vehicle ID to public key, signed by CA |
| `gsk(vid, gmsk)` | Group secret key derived from vehicle ID and group master secret key |
| `pseudocert(pseudopk, gsk)` | Pseudonym certificate for anonymous message signing |
| `gsign(m, gsk)` | Group signature (unused in current model — pseudonyms used instead) |
| `aenc(m, pk)` / `sign(m, sk)` | Standard asymmetric encryption and digital signatures |

### Protocol phases

1. **Phase 0 (Registration)**: Vehicle requests a group key from CA/RSU by sending an encrypted and signed request. CA verifies the enrollment certificate and responds with a `gsk`.
2. **Phase 1 (Revocation)**: A vehicle reports a malicious pseudonym certificate. CA extracts the `vid` via `gopen`, adds it to the revocation table, generates a new `gmsk`, and transitions to phase 2.
3. **Phase 2 (Re-registration)**: Non-revoked vehicles request a new group key under the updated `gmsk`. Revoked vehicles are rejected.

## Verified Properties

### Q1 — Sanity Checks

| Query | Description | Result |
|-------|-------------|--------|
| Q1.1 | Vehicle can obtain a valid group key | **Not false** (attainable) |
| Q1.2 | Attacker can obtain a valid group key | **True** (attacker gets enrollment cert) |
| Q1.3 | Revoked vehicle cannot obtain a group key | **True** (when properly reported) |
| Q1.4 | Vehicle can send a broadcast message | **Not false** (attainable) |
| Q1.5 | Attacker can send a broadcast message | **True** (with enrollment cert) |
| Q1.6 | No double-revocation event | **Not false** (no false `AlreadyRevoked`) |
| Q1.7 | Attacker can revoke another vehicle | **Not false** (requires enrollment cert) |

### Q2 — Authentication

| Query | Description | Result |
|-------|-------------|--------|
| Q2.1 | CA authentication to vehicle during registration | **True** |
| Q2.2 | Vehicle authentication to CA during registration | **True** (unless attacker has enrollment cert) |

### Q3 — Weak Secrecy (Vehicle Identity)

| Scenario | Leakage | Result |
|----------|---------|--------|
| CA Secret Key (cask) leaked | `CASecretKeyReveal(cask)` | **Attack found** — attacker can decrypt registration and extract `vid` |
| Group Master Secret Key (gmsk) leaked | `GroupMasterSecretKeyReveal(gmsk)` | **Attack found** — attacker links pseudonym certs to `vid` via `gopen` |
| Neither leaked | None | `vid` remains secret |

### Temporal Properties (Qx)

| Query | Description | Result |
|-------|-------------|--------|
| Qx.x | RevokedCannotGetGroupKey must occur after RevokedVid | **Cannot be proved** (ordering issue) |
| Qx.2 | Message from revoked vehicle cannot be received after revocation | **Attack found** — attacker replays old message with old pseudonym cert and new key |
| Qx.3 | Receive event must precede revoke event | **False** — attack trace found |

### Perfect Forward Secrecy (PFS)

| Scenario | Result |
|----------|--------|
| Attacker obtains gmsk after phase 0 | Session key not compromised |
| Additional scenarios | Tested under phase 1, phase 2, single/multiple vehicles |

### Offline Guessing Attacks

| Secret | Result |
|--------|--------|
| `vid` | Strong secrecy holds |
| `encsignreq` | Strong secrecy holds |
| `encsignresp` | Strong secrecy holds |

### Q6 — Unlinkability

Unlinkability is verified using **observational equivalence**: the protocol with multiple message sends per vehicle is compared against a version with a single send.

| Model variant | Nonce | Revocation | Result |
|---------------|-------|------------|--------|
| `0_pre` (replicated vehicles) | No | Yes | Attack traces found (17 traces) |
| `traces1_without_nonce` | No | No | Attack traces found |
| `traces2_with_nonce_and_revocation_part` | Yes | Yes | Attack traces found (4 traces) |
| `traces3_with_nonce_without_revocation_part` | Yes | No | Attack traces found (2 traces) |

## Results Summary

The protocol guarantees **authentication** and basic **sanity properties**, but several vulnerabilities exist:

1. **Enrollment certificate leakage**: An attacker who obtains an enrollment certificate can register with the CA, revoke other vehicles, and send valid broadcast messages.
2. **Key leakage**: If the CA secret key (cask) is compromised, the attacker can decrypt registration messages and recover vehicle identities. If the Group Master Secret Key (gmsk) is compromised, the attacker can link pseudonym certificates to vehicle identities.
3. **Replay attacks**: A revoked vehicle's message can be replayed after revocation by combining an old pseudonym certificate with a new group key signature.
4. **Unlinkability attacks**: The current protocol design does not provide full unlinkability — an observer can link multiple messages to the same vehicle.

## Attack Traces

Each `.pdf` file in the `leakage_cask/traces q*/`, `leakage_gmsk/traces q*/`, and `unlinkability/` directories contains ProVerif's attack trace output (also available as `.dot` files for Graphviz rendering).

## References

- `sources/manual.pdf` — ProVerif manual
- `sources/Pseudonym_Schemes_in_Vehicular_Networks.pdf` — Pseudonym schemes for V2X
- `sources/Efficient and robust pseudonymous authentication.pdf` — Efficient pseudonymous authentication
- `sources/Formal Verification of a v2x privacy preserving scheme.pdf` — Prior work on formal verification of V2X
- `Report_formal_verification_of_a_V2X_protocol.pdf` — Full thesis/report for this project

## Author

Matteo Pedone
