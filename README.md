# AVASTA - ANDROID VULNERABILITY ASSESSMENT and SECURITY TESTING AID
Android app vulnerability scanner

## avasta.py
This python script serves as an automated vulnerability assessment and security testing tool for Android applications. It systematically decompiles APK files, analyzes the resultant Smali code. It searches for predefined patterns that indicate security weaknesses, presenting a detailed report of the identified vulnerabilities and recommended mitigation strategies. . Its systematic approach aims to provide a comprehensive overview of potential security weaknesses within the decompiled codebase, facilitating a more informed understanding of an application's security posture.

## Required Dependencies
```
apktool       # sudo apt install apktool
python3       # sudo apt install python3-pip
tabulate      # pip3 install tabulate
```
## Example Output
https://github.com/fiyanmehfil/AVASTA/assets/112199644/643a329d-1f6b-47fa-999e-71d95fe517c6

## Current Security Checks
1. Potential Secrets
2. Insecure Data Storage
3. Code Injection Issues
4. Sensitive Data Exposure
5. Inadequate Input Validation
6. Unhandled Exceptions
7. Insecure Communication
8. Improper Permission Handling
9. Insecure Code Execution
10. Broken Authentication
11. Potentially Risky Files
12. Code Quality Issues
