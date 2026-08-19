# IKB42603 Cloud Computing Security Essentials

### Lab 3: Data Protection: Encryption & Key Management

**Name:** UZAIR BIN SAMSUDIN  
**ID:** 52215124300  

---

## 1. Objective

This lab demonstrates how to safeguard cloud data confidentiality and integrity across data at rest and data in transit. The primary goal is to implement fundamental symmetric (AES-256) and asymmetric (RSA) cryptographic controls, protect network transit channels using TLS, manage scalable encryption via cloud Key Management Services (LocalStack KMS) and envelope encryption, execute provable cryptographic erasure across multi-tenant contexts, and construct tamper-evident hash-chained logs.

---

## 2. Learning Outcomes

Upon completion of this lab, the student will be able to:
* Encrypt and decrypt data with symmetric (AES) and asymmetric (RSA) cryptography.
* Protect data in transit with TLS and observe the difference between plaintext and encrypted traffic.
* Use a Key Management Service (KMS) and implement envelope encryption.
* Apply per-tenant keys and perform cryptographic erasure to make data provably unrecoverable.
* Verify data integrity with hashing and build a tamper-evident (hash-chained) record.

---

## 3. Environment

| Component | Detail |
| :--- | :--- |
| **OS** | Kali Linux (`amd64`, kernel 6.16.8) |
| **Container Runtime** | Docker Engine v28.5.2 |
| **Cryptography Tool** | OpenSSL v3.6.3 (CLI) |
| **Cloud Emulation Tool** | LocalStack Community v3.8.0 (KMS on port 4566) |
| **CLI Tools** | `openssl`, `aws-cli` v2.36.9, `docker`, `curl`, `sha256sum`, `diff` |
| **Web Server Container** | Nginx Alpine (TLS endpoint on port 8443) |
| **Session A Focus** | Symmetric/asymmetric encryption; data at rest and in transit (Tasks 1–3) |
| **Session B Focus** | KMS, envelope encryption, per-tenant keys, cryptographic erasure, integrity (Tasks 4–7) |

> [!TIP]
> **Security Tip:** Encryption is only as strong as its key management. Watch carefully where the keys live—that is the real security control, not merely the algorithm.

---

## 4. Step-by-Step Implementation

### Session A (Week 5) — Encryption Fundamentals

#### Task 1 — Symmetric Encryption (Data at Rest)

A sensitive plaintext record was created and encrypted at rest with AES-256-CBC using PBKDF2 key derivation and salting. The encrypted file was inspected to verify illegibility and decrypted to validate recovery.

```bash
# Create a sample sensitive record
echo 'Patient: Amira, Diagnosis: confidential' > record.txt

# Encrypt with AES-256 (prompted for passphrase)
openssl enc -aes-256-cbc -pbkdf2 -salt -in record.txt -out record.enc

# Prove it is unreadable
cat record.enc

# Decrypt back
openssl enc -d -aes-256-cbc -pbkdf2 -in record.enc -out record.dec.txt

# Verify match
diff record.txt record.dec.txt && echo 'MATCH: decryption successful'
```

* **Result:** `record.enc` displayed scrambled binary data starting with `Salted__`. Running `diff` against `record.dec.txt` returned `MATCH: decryption successful`, proving reversible symmetric protection.

#### Task 2 — Asymmetric Encryption & Digital Signatures

A 2048-bit RSA key pair was generated. The public key was used for data encryption and signature verification, while the private key performed data decryption and signature generation.

```bash
# Generate 2048-bit RSA key pair
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Encrypt with PUBLIC key, decrypt with PRIVATE key
openssl pkeyutl -encrypt -pubin -inkey public.pem -in record.txt -out record.rsa
openssl pkeyutl -decrypt -inkey private.pem -in record.rsa -out record.rsa.txt

# Sign with PRIVATE key; verify with PUBLIC key
openssl dgst -sha256 -sign private.pem -out record.sig record.txt
openssl dgst -sha256 -verify public.pem -signature record.sig record.txt
```

* **Result:** Decryption with `private.pem` restored `Patient: Amira, Diagnosis: confidential`. Digital signature verification with `public.pem` returned `Verified OK`, confirming message integrity, origin authenticity, and non-repudiation.

#### Task 3 — Encryption in Transit (TLS)

A self-signed X.509 certificate and private key were generated. An Nginx container was deployed on HTTPS port 8443 serving `record.txt` over TLS to protect data in transit against eavesdropping.

```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 7 -nodes -subj '/CN=localhost'

# Serve HTTPS on port 8443 using an Nginx container
docker run --rm -d --name tls -p 8443:443 \
  -v $(pwd)/cert.pem:/etc/ssl/certs/cert.pem \
  -v $(pwd)/key.pem:/etc/ssl/private/key.pem \
  -v $(pwd)/record.txt:/usr/share/nginx/html/record.txt \
  nginx sh -c 'echo "server { listen 443 ssl; ssl_certificate /etc/ssl/certs/cert.pem; ssl_certificate_key /etc/ssl/private/key.pem; location / { root /usr/share/nginx/html; } }" > /etc/nginx/conf.d/default.conf && nginx -g "daemon off;"'

# Connect over TLS (-k accepts self-signed cert)
curl -k https://localhost:8443/record.txt

# Teardown TLS container
docker stop tls
```

* **Result:** The `curl -k` command successfully established a TLS session and retrieved the patient record securely over port 8443 without plaintext exposure on the network.

---

### Session B (Week 6) — Key Management, Envelope Encryption & Erasure

#### Task 4 — Create and Use a KMS Master Key

A Customer Master Key (CMK) was provisioned in LocalStack KMS for Tenant A to manage keys within a centralized cloud key store. A small test secret was encrypted directly using the KMS API.

```bash
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export EP='--endpoint-url=http://localhost:4566'

# Create Tenant A CMK
KEY_A=$(aws $EP kms create-key --description 'CCSE tenant-A master key' --query 'KeyMetadata.KeyId' --output text)
echo "Tenant A Key ID: $KEY_A"

# Direct KMS Encrypt
aws $EP kms encrypt --key-id "$KEY_A" --plaintext "$(echo -n 'hello' | base64)" --query CiphertextBlob --output text
```

* **Result:** KMS generated Tenant A Key ID `5805a7a0-ad4c-49a6-9c73-daf0ba6b3f50` and returned the encrypted base64 payload `NTgwN....`

#### Task 5 — Envelope Encryption

To encrypt large files without streaming bulk data through the KMS, envelope encryption was implemented: KMS generated a Data Encryption Key (DEK), `record.txt` was encrypted locally with the plaintext DEK, and the plaintext DEK was destroyed, retaining only the KMS-wrapped key.

```bash
# 5.1 Request Data Key from KMS
DATA_KEY_OUT=$(aws $EP kms generate-data-key --key-id "$KEY_A" --key-spec AES_256 --query '[Plaintext, CiphertextBlob]' --output text)

echo "$DATA_KEY_OUT" | awk '{print $1}' > datakey.b64
echo "$DATA_KEY_OUT" | awk '{print $2}' | base64 -d > datakey.enc

# 5.2 Encrypt locally with PLAINTEXT data key
base64 -d datakey.b64 > datakey.bin
openssl enc -aes-256-cbc -pbkdf2 -in record.txt -out record.env.enc -pass file:./datakey.bin

# 5.3 Destroy plaintext data key from disk
rm datakey.bin datakey.b64
echo 'Only the KMS-wrapped data key (datakey.enc) remains.'
ls -l record.env.enc datakey.enc
```

* **Result:** `record.env.enc` was produced locally with AES-256. Plaintext data key artifacts were purged; `ls -l` confirmed that only `datakey.enc` (116 bytes) and `record.env.enc` (64 bytes) remained.

#### Task 6 — Per-Tenant Keys & Cryptographic Erasure

An independent CMK was created for Tenant B to verify tenant key segregation. Tenant A's key was scheduled for deletion to demonstrate cryptographic erasure (crypto-shredding).

```bash
# Create separate CMK for Tenant B
KEY_B=$(aws $EP kms create-key --description 'CCSE tenant-B master key' --query 'KeyMetadata.KeyId' --output text)
echo "Tenant B Key ID: $KEY_B"

# Schedule deletion of Tenant A's key (7-day window)
aws $EP kms schedule-key-deletion --key-id "$KEY_A" --pending-window-in-days 7

# Attempt to disable key (locked in PendingDeletion)
aws $EP kms disable-key --key-id "$KEY_A"

# Attempt to unwrap data key (Expected to FAIL)
aws $EP kms decrypt --ciphertext-blob fileb://datakey.enc 2>&1 | head -5
```

* **Result:** Tenant B received Key ID `0c895383-f1cb-46da-b16c-ee521de962a5`. Tenant A entered `PendingDeletion` state. The `aws kms decrypt` attempt failed with `KMSInvalidStateException`, proving `record.env.enc` is mathematically unrecoverable.

#### Task 7 — Integrity & Tamper-Evidence

Cryptographic hashing (SHA-256) was used to verify file integrity and detect alterations. A forward-chained hash loop was built to model a tamper-evident audit log structure.

```bash
# Fingerprint original file
sha256sum record.txt

# Tamper with copy and show hash divergence
cp record.txt tampered.txt
echo 'x' >> tampered.txt
sha256sum record.txt tampered.txt

# Rolling tamper-evident hash chain
PREV=0
for line in 'login ok' 'file read' 'export data'; do
  PREV=$(echo -n "$PREV$line" | sha256sum | cut -d' ' -f1)
  echo "$line | $PREV"
done
```

* **Result:** Modifying one character produced a completely diverged hash digest (`fea964ac...`). The 3-step hash chain computed rolling hashes where each record is cryptographically tied to prior entries.

---

## 5. Commands Used

| Command | Task | Purpose |
| :--- | :--- | :--- |
| `openssl enc -aes-256-cbc -pbkdf2 ...` | Task 1 | Encrypt and decrypt data symmetrically using AES-256 |
| `diff record.txt record.dec.txt` | Task 1 | Verify identity between original and decrypted files |
| `openssl genrsa -out private.pem 2048` | Task 2 | Generate a 2048-bit RSA private key |
| `openssl rsa -in private.pem -pubout ...` | Task 2 | Extract public key from private RSA key |
| `openssl pkeyutl -encrypt / -decrypt ...` | Task 2 | Asymmetric encryption/decryption with public/private keys |
| `openssl dgst -sha256 -sign / -verify ...` | Task 2 | Generate and verify RSA-SHA256 digital signatures |
| `openssl req -x509 -newkey rsa:2048 ...` | Task 3 | Generate self-signed X.509 TLS certificate |
| `docker run ... nginx` | Task 3 | Deploy Nginx container serving custom TLS endpoint |
| `curl -k https://localhost:8443/...` | Task 3 | Retrieve record over encrypted TLS transit tunnel |
| `aws kms create-key ...` | Tasks 4 & 6 | Provision tenant CMKs within LocalStack KMS |
| `aws kms encrypt ...` | Task 4 | Directly encrypt small data secret via KMS API |
| `aws kms generate-data-key ...` | Task 5 | Request plaintext and wrapped DEK for envelope encryption |
| `rm datakey.bin datakey.b64` | Task 5 | Purge plaintext key material from disk |
| `aws kms schedule-key-deletion ...` | Task 6 | Schedule CMK deletion to trigger cryptographic erasure |
| `aws kms decrypt ...` | Task 6 | Attempt to unwrap DEK (demonstrating erasure failure) |
| `sha256sum ...` | Task 7 | Compute SHA-256 cryptographic fingerprints |
| `aws kms list-keys` | Deliverables | Enumerate all tenant keys within LocalStack KMS |
| `docker stop / rm ...` | Teardown | Terminate containers and purge temporary lab artifacts |

---

## 6. Screenshots

### Screenshot 1 — Task 1: Symmetric Encryption (Data at Rest)

![Screenshot 1 — Task 1 Symmetric Encryption (Data at Rest)](./Screenshot%201%20—%20Task%201%20Symmetric%20Encryption%20(Data%20at%20Rest).png)

**Findings:**
* Symmetrical encryption using AES-256-CBC with PBKDF2 converted `record.txt` into illegible binary ciphertext `record.enc` (`Salted__...`).
* Decryption using the identical passphrase restored `record.dec.txt`.
* `diff` comparison between `record.txt` and `record.dec.txt` printed `MATCH: decryption successful`, confirming data restoration.

### Screenshot 2 — Task 2: Asymmetric Encryption & Digital Signatures

![Screenshot 2 — Task 2 Asymmetric Encryption & Digital Signatures](./Screenshot%202%20—%20Task%202%20Asymmetric%20Encryption%20&%20Digital%20Signatures.png)

**Findings:**
* Generated a 2048-bit RSA key pair (`private.pem` and `public.pem`).
* Encrypted `record.txt` with `public.pem` and successfully decrypted it using `private.pem`, displaying `Patient: Amira, Diagnosis: confidential`.
* Signed the file hash with `private.pem` to generate `record.sig`; verification with `public.pem` returned `Verified OK`, confirming message origin and non-repudiation.

### Screenshot 3 — Task 3: Encryption in Transit (TLS)

![Screenshot 3 — Task 3 Encryption in Transit (TLS)](./Screenshot%203%20—%20Task%203%20Encryption%20in%20Transit%20(TLS).png)

**Findings:**
* Generated a self-signed TLS certificate (`cert.pem`) and private key (`key.pem`).
* Hosted an Nginx container serving `record.txt` over HTTPS on port 8443.
* `curl -k` retrieved `Patient: Amira, Diagnosis: confidential` across an encrypted TLS channel, protecting payload data from cleartext network sniffing.

### Screenshot 4 — Task 4: Create and Use a KMS Master Key

![Screenshot 4 — Task 4 Create and Use a KMS Master Key](./Screenshot%204%20—%20Task%204%20Create%20and%20Use%20a%20KMS%20Master%20Key.png)

**Findings:**
* LocalStack KMS provisioned a dedicated CMK for Tenant A with Key ID `5805a7a0-ad4c-49a6-9c73-daf0ba6b3f50`.
* Encrypting a secret payload directly with KMS returned a valid base64 `CiphertextBlob` (`NTgwN...`), confirming centralized key management.

### Screenshot 5 — Task 5: Envelope Encryption

![Screenshot 5 — Task 5 Envelope Encryption](./Screenshot%205%20—%20Task%205%20Envelope%20Encryption.png)

**Findings:**
* KMS generated an AES-256 Data Encryption Key (DEK), returning plaintext and wrapped components.
* `record.txt` was encrypted locally with the plaintext DEK into `record.env.enc`.
* Plaintext DEK files were removed; `ls -l` confirmed only `datakey.enc` (116 bytes) and `record.env.enc` (64 bytes) remained on disk.

### Screenshot 6 — Task 6: Per-Tenant Keys & Cryptographic Erasure

![Screenshot 6 — Task 6 Per-Tenant Keys & Cryptographic Erasure](./Screenshot%206%20—%20Task%206%20Per-Tenant%20Keys%20&%20Cryptographic%20Erasure.png)

**Findings:**
* Provisioned an isolated CMK for Tenant B (`0c895383-f1cb-46da-b16c-ee521de962a5`).
* Scheduled deletion of Tenant A's CMK, transitioning its state to `PendingDeletion`.
* Attempting `aws kms decrypt` on Tenant A's wrapped key failed with `KMSInvalidStateException`, proving `record.env.enc` is mathematically unrecoverable.

### Screenshot 7 — Task 7: Integrity & Tamper-Evidence

![Screenshot 7 — Task 7 Integrity & Tamper-Evidence](./Screenshot%207%20—%20Task%207%20Integrity%20&%20Tamper-Evidence.png)

**Findings:**
* Generated baseline SHA-256 hash for `record.txt` (`f7643a1cbfdd...`).
* Appending a single character in `tampered.txt` produced complete hash divergence (`fea964ac...`).
* Forward hash chain executed across three log records (`login ok`, `file read`, `export data`), creating a verifiable, tamper-evident audit trail.

### Screenshot 8 — Deliverables: Verification Commands

![Screenshot 8 — Deliverables: Verification Commands](./Screenshot%208%20—%20Verification%20Commands.png)

**Findings:**
* `aws kms list-keys` enumerated both provisioned tenant keys in LocalStack (`5805a7a0...` and `0c895383...`).
* Digital signature verification against `record.sig` returned `Verified OK`.
* Final cleanup removed all lab artifacts and stopped Docker containers.

---

## 7. Short-Answer Questions

### Q1. Compare symmetric and asymmetric encryption: speed, key distribution, and typical use.

| Comparison Dimension | Symmetric Encryption (e.g., AES-256) | Asymmetric Encryption (e.g., RSA-2048) |
| :--- | :--- | :--- |
| **Computational Speed** | Extremely fast and computationally lightweight; uses substitution-permutation networks. | Significantly slower; requires intensive modular exponentiation of large prime numbers. |
| **Key Distribution** | Complex: Both parties must securely share a single secret key out-of-band. | Simple: Public key is distributed openly; private key is kept confidential. |
| **Typical Cloud Use** | Bulk data encryption at rest (block storage, S3 object storage, database tables). | Identity authentication, digital signatures, and TLS key exchange (session key wrapping). |

In cloud architectures, symmetric key distribution across millions of clients is impractical. Cloud systems resolve this by using asymmetric cryptography during TLS handshakes to securely negotiate a shared symmetric session key, which is then used for high-speed bulk data transport.

### Q2. Why is key management described as the weakest link, not the algorithm?

Modern cryptographic ciphers such as AES-256 and RSA-2048 are mathematically sound; cracking AES-256 via brute force is computationally impossible with existing computing power. Instead, cryptographic failures almost exclusively occur within the key management lifecycle:

* **Insecure Key Storage:** Hardcoding encryption keys in application source code or leaving plaintext keys on local disks.
* **Over-Permissive Access Policies:** Misconfigured IAM roles allowing unauthorized users or services to call KMS decryption APIs.
* **Lack of Rotation:** Using a single key indefinitely increases the blast radius if the key is compromised.
* **Key Interception:** Distributing shared secrets over unencrypted communication channels.

If an attacker steals the key, the mathematical complexity of the algorithm becomes irrelevant; the encryption is completely bypassed.

### Q3. Explain envelope encryption and why only the master key needs hardware-grade protection.

Envelope encryption is a hierarchical key management strategy:
1. A unique Data Encryption Key (DEK) is generated to encrypt the actual data payload locally using fast symmetric encryption (AES-256).
2. The DEK itself is encrypted (wrapped) using a Customer Master Key (CMK) stored inside a KMS / Hardware Security Module (HSM).
3. The plaintext DEK is purged from memory and disk, storing only the KMS-wrapped DEK alongside the ciphertext.

```
+-----------------------------------------------------------+
| Plaintext Data  ---> [ Encrypt with Plaintext DEK ]       |
|                             |                             |
|                             v                             |
|                      Ciphertext Data                      |
|                             +                             |
| Plaintext DEK   ---> [ Encrypt with Master Key in KMS ]   |
|                             |                             |
|                             v                             |
|                        Wrapped DEK                        |
+-----------------------------------------------------------+
```

**Why only the Master Key needs hardware-grade protection:**
* **Performance & Network Efficiency:** Streaming large multi-gigabyte files to an HSM over a network introduces severe bandwidth bottlenecks.
* **Scalability:** By encrypting large files locally with DEKs, the HSM only handles small 256-bit key-wrapping operations.
* **Root of Trust:** Protecting the root CMK within certified HSM boundaries guarantees that unwrapping the DEK requires authenticated, audited KMS API requests without exposing the master key outside the hardware enclave.

### Q4. How does cryptographic erasure achieve provable deletion where overwriting cannot (in the cloud)?

In multi-tenant cloud storage, physical media is abstracted behind virtualization, automatic volume replication, distributed object stores, and disaster-recovery snapshots.

* **Overwriting Limitations:** Cloud tenants lack direct access to physical storage sectors or flash memory cells to execute zero-fills (`dd`) or degaussing. Furthermore, overwriting one logical volume does not guarantee that distributed background snapshots or cached replicas are sanitized.
* **Cryptographic Erasure (Crypto-Shredding):** Data is encrypted at rest with dedicated per-tenant or per-dataset keys. When deletion is requested, the associated master key in the KMS is destroyed.

Without the master key, all ciphertext and replicas across all backup storage become permanently unrecoverable mathematical noise instantaneously, providing verifiable and auditable data deletion.

### Q5. How does a hash chain make a log tamper-evident?

A hash chain enforces a forward mathematical dependency where each log entry's cryptographic digest is computed from its own data concatenated with the hash of the preceding record:

$$\text{Hash}_n = \text{SHA256}(\text{Hash}_{n-1} \parallel \text{Log Entry}_n)$$

* **Tamper Evidence:** If an attacker modifies, deletes, or inserts an entry at position $k$, the hash at $k$ changes. Because every downstream entry ($k+1, k+2, \dots$) incorporates the preceding hash, all subsequent digests in the chain become invalid.
* **Verification:** An auditor can recompute the chain sequentially from genesis; any mismatch immediately detects tampering and isolates the modified log record.

---

## 8. Challenges Encountered

| Challenge | Resolution |
| :--- | :--- |
| **Premature Container Termination during TLS Test** | Running `curl` concurrently with `docker stop tls` resulted in `curl: (35) Send failure: Broken pipe`. Resolved by decoupling container launch, validating the TLS endpoint, and issuing `docker stop` only after verification. |
| **LocalStack Port Allocation Conflict** | Attempting to launch LocalStack failed with `Bind for 0.0.0.0:4566 failed: port is already allocated`. Resolved by killing lingering processes using `sudo fuser -k 4566/tcp` and removing old containers via `docker rm -f localstack`. |
| **LocalStack Pro License Exit (Code 55)** | Pulling the `:latest` LocalStack image defaulted to a Pro build requiring an activation token. Resolved by explicitly pinning the container to the free community release (`localstack/localstack:3.8.0`). |
| **AWS KMS State Lock on Pending Deletion** | Calling `disable-key` on Tenant A returned `KMSInvalidStateException`. Understood that scheduling key deletion automatically transitions the key to `PendingDeletion`, rendering explicit disable calls redundant. |
| **Binary Data Key Formatting** | Passing raw base64 data key strings into `fileb://` caused decryption parsing errors. Resolved by decoding base64 output into raw binary format (`datakey.bin` / `datakey.enc`) prior to OpenSSL and KMS operations. |

---

## 9. Lessons Learned

* **Key Governance as the Core Security Boundary:** Mathematical cipher strength is only effective when supported by secure key lifecycle management, including role-based access, rotation, and hardware isolation.
* **Architectural Value of Envelope Encryption:** Envelope encryption bridges the gap between high-performance local processing and centralized cloud key security, reducing network latency while preserving centralized access auditing.
* **Provable Deletion via Cryptographic Shredding:** In distributed multi-tenant cloud environments where physical media cannot be sanitized directly, cryptographic erasure serves as the definitive method for permanent, auditable data destruction.
* **Layered Defense across Data States:** Comprehensive cloud data protection requires integrated security controls: AES-256 for data at rest, TLS for data in transit, RSA signatures for authenticity, and hash chains for audit integrity.

---

## 10. References

1. OpenSSL Documentation: Cryptographic Command-Line Utilities, [www.openssl.org/docs](https://www.openssl.org/docs)
2. AWS KMS Documentation: Envelope Encryption & Key Management Concepts, [docs.aws.amazon.com/kms](https://docs.aws.amazon.com/kms)
3. Cloud Security Alliance (CSA): Security Guidance for Critical Areas of Focus in Cloud Computing v5 — Data Security & Encryption.
4. NIST SP 800-57 Part 1 Rev. 5: Recommendation for Key Management, National Institute of Standards and Technology.
5. NIST SP 800-88 Rev. 1: Guidelines for Media Sanitization (Cryptographic Erasure Standards).
6. IKB42603 Course Lectures: Week 4 (Data Protection) & Week 9 (Key Management Patterns), UniKL MIIT, Prof. Dr. Shahrulniza Musa.
