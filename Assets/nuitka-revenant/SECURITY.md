# Security policy

## Reporting a vulnerability

Do not open a public issue for vulnerabilities that could put users or their data at immediate risk. Use GitHub's private vulnerability-reporting feature when it is enabled for this repository.

Include the affected revision, reproduction steps, impact and any proposed mitigation. Do not include real credentials, proprietary binaries or personal information.

## Untrusted targets

The default recovery workflow is static, but input binaries and extracted artifacts must still be treated as untrusted data:

- work in an isolated analysis environment;
- never launch an unknown target as part of static recovery;
- inspect generated Python before executing it;
- keep dynamic injection disabled unless you are in an authorized laboratory;
- do not assume parseable recovered output is safe or semantically correct.

Generated source can preserve malicious behavior from the analyzed program. REVENANT does not sanitize recovered logic.
