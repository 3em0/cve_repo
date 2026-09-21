# Security Vulnerability Report: Langchain-Chatchat Image Hash Collision and File Service Vulnerabilities

## Summary

Multiple vulnerabilities were discovered in Langchain-Chatchat (v0.3.x), an open-source RAG and Agent application with 37.7k GitHub stars. The core issue is that `PIL.Image.tobytes()` is used to compute an MD5 hash as a server-side filename for pasted images, discarding palette metadata and enabling hash collision attacks. Combined with server-side file storage flaws, this allows cross-user image replacement and LLM input poisoning in multi-tenant deployments.

## Vendor Information

| Field | Value |
|-------|-------|
| **Vendor** | chatchat-space (https://github.com/chatchat-space) |
| **Product** | Langchain-Chatchat (formerly Langchain-ChatGLM) |
| **Repository** | https://github.com/chatchat-space/Langchain-Chatchat |
| **Affected Version** | 0.3.x (at least 0.3.1.3) |
| **License** | Apache-2.0 |

## Vulnerabilities

| # | Vulnerability | CWE | Severity |
|---|--------------|-----|----------|
| 1 | [Image Hash Collision via tobytes() Metadata Loss](Vuln-1-tobytes-Hash-Collision.md) | CWE-328 | Medium |
| 2 | [Silent File Overwrite via Filename-as-Path-Key Storage](Vuln-2-Silent-File-Overwrite.md) | CWE-367 | Medium |
| 3 | [Predictable File Identifier](Vuln-3-Predictable-File-ID.md) | CWE-330 | Medium |
| 4 | [Missing Authentication on File Service Endpoints](Vuln-4-Missing-Auth-File-Endpoints.md) | CWE-862 | High |

## Credits

- Vulnerability Discovery: [dem0]
- Vulnerability Analysis: [dem0]
