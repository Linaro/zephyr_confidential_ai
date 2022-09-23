# Confidential AI Provisioning Process

## Provisioning Workflow

```
title Confidential AI Provisioning Process

Secure->Secure:Initialise
Non-Secure->Non-Secure:Initialise
Provisioning Tool->CA:Request CA/TLS Certs (one-time)
CA->Provisioning Tool: Send CA/TLS Certs
Provisioning Tool->Cloud Server: Request TLS and ENCRYPT certs (one-time)
Cloud Server->Provisioning Tool: Send TLS/ENCRYPT certs
Provisioning Tool->Non-Secure: Send provisioning request
Provisioning Tool->Non-Secure: Forward CA/TLS Certs
Provisioning Tool->Non-Secure: Forward Cloud TLS/ENCRYPT certs
Non-Secure->Non-Secure: Store Certs

loop Key Generation Process
Non-Secure->Secure:Request Client TLS/SIGN/ENCRYPT keygen
Secure->Secure: Generate and store private keys
Non-Secure->Secure: Request public key via key handles
Secure->Non-Secure: Send public key(s)
Non-Secure->Non-Secure: Generate CSRs
Non-Secure->Secure: Request CSR signatures
Secure->Non-Secure: Return signed requests
Non-Secure->Provisioning Tool: Send CSRs
Provisioning Tool->CA: Forward CSRs
CA->CA: Process CSRs, Generate/register certs
CA->Provisioning Tool: Send certs
Provisioning Tool->Non-Secure: Forward certs
Non-Secure->Non-Secure: Store certs
Non-Secure->Provisioning Tool: Indicate done
end

Provisioning Tool->CA: Indicate provisioning done
CA->CA: Mark certs as active in DB
```
