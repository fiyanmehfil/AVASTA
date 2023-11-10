import re
import os
import argparse
import subprocess
from prettytable import PrettyTable

RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

# Define patterns for potential secrets (you can extend this list)
secret_patterns = ["api_key", "password", "secret_key"]
secret_mitigations = {
    "api_key": "Store API keys securely using environment variables.",
    "password": "Implement strong password hashing and storage practices.",
    "secret_key": "Use a secure vault or secret management system for secret keys.",
}

# Define patterns for insecure data storage
insecure_storage_patterns = ["SharedPreferences.Editor;->commit"]
insecure_storage_mitigations = {
    "SharedPreferences.Editor;->commit": "Use apply() instead of commit() for shared preferences.",
}

# Define patterns for code injection issues (SQL injection, XSS, etc.)
code_injection_patterns = ["SQLiteDatabase;->execSQL", "WebView;->loadUrl"]
code_injection_mitigations = {
    "SQLiteDatabase;->execSQL": "Use parameterized queries to prevent SQL injection.",
    "WebView;->loadUrl": "Sanitize and validate user inputs when using WebView loadUrl().",
}

# Define patterns for sensitive data exposure
sensitive_data_patterns = ["Log;->d\\(Ljava/lang/String;Ljava/lang/String;\\)", "Log;->i\\(Ljava/lang/String;Ljava/lang/String;\\)"]
sensitive_data_mitigations = {
    "Log;->d\\(Ljava/lang/String;Ljava/lang/String;\\)": "Avoid logging sensitive data in production code.",
    "Log;->i\\(Ljava/lang/String;Ljava/lang/String;\\)": "Avoid logging sensitive data in production code.",
}

# Define patterns for inadequate input validation
input_validation_patterns = ["Landroid/text/TextUtils;->isEmpty\\(Ljava/lang/CharSequence;\\)Z", "Ljava/util/regex/Pattern;->matcher\\(Ljava/lang/CharSequence;\\)Ljava/util/regex/Matcher;"]
input_validation_mitigations = {
    "Landroid/text/TextUtils;->isEmpty\\(Ljava/lang/CharSequence;\\)Z": "Validate user inputs and enforce input constraints.",
    "Ljava/util/regex/Pattern;->matcher\\(Ljava/lang/CharSequence;\\)Ljava/util/regex/Matcher;": "Use input validation and sanitation to prevent regex-based attacks.",
}

# Define patterns for unhandled exceptions
exception_patterns = ["Ljava/lang/Exception;->printStackTrace\\(\\)V"]
exception_mitigations = {
    "Ljava/lang/Exception;->printStackTrace\\(\\)V": "Properly handle exceptions and avoid printing stack traces in production code.",
}

# Define patterns for insecure communication
insecure_communication_patterns = ["Landroid/net/HttpURLConnection;->setHostnameVerifier\\(Ljavax/net/ssl/HostnameVerifier;\\)"]
insecure_communication_mitigations = {
    "Landroid/net/HttpURLConnection;->setHostnameVerifier\\(Ljavax/net/ssl/HostnameVerifier;\\)": "Implement proper hostname verification and use secure communication protocols.",
}

# Define patterns for improper permission handling
improper_permission_patterns = ["Landroid/app/Activity;->checkSelfPermission\\(Ljava/lang/String;\\)I"]
improper_permission_mitigations = {
    "Landroid/app/Activity;->checkSelfPermission\\(Ljava/lang/String;\\)I": "Properly handle and request permissions in Android apps.",
}

# Define patterns for insecure code execution
insecure_code_execution_patterns = ["Runtime;->exec", "ProcessBuilder;->start"]
insecure_code_execution_mitigations = {
    "Runtime;->exec": "Avoid executing external commands with user-controlled inputs.",
    "ProcessBuilder;->start": "Ensure command parameters are not controlled by user inputs.",
}

# Define patterns for broken authentication
broken_auth_patterns = ["checkSelfPermission\\(Ljava/lang/String;\\)", "Landroid/content/pm/PackageManager;->checkPermission\\(Ljava/lang/String;Ljava/lang/String;\\)"]
broken_auth_mitigations = {
    "checkSelfPermission\\(Ljava/lang/String;\\)": "Ensure proper permission checks and authentication mechanisms.",
    "Landroid/content/pm/PackageManager;->checkPermission\\(Ljava/lang/String;Ljava/lang/String;\\)": "Verify permissions using PackageManager.",
}

# Define patterns for potentially risky files
risk_file_patterns = ["backup.db", "config.properties", "secrets.xml"]
risk_file_mitigations = {
    "backup.db": "Avoid storing sensitive data in backup files.",
    "config.properties": "Ensure that configuration files are not accessible to unauthorized users.",
    "secrets.xml": "Securely store secrets and encryption keys, and protect XML files from unauthorized access.",
}

# Define patterns for code quality
code_quality_patterns = ["Landroid/util/Log;->e\\(Ljava/lang/String;Ljava/lang/String;\\)", "Landroid/util/Log;->w\\(Ljava/lang/String;Ljava/lang/String;\\)"]

code_quality_mitigations = {
    "Landroid/util/Log;->e\\(Ljava/lang/String;Ljava/lang/String;\\)": "Avoid using Log.e() for non-error logs in production code.",
    "Landroid/util/Log;->w\\(Ljava/lang/String;Ljava/lang/String;\\)": "Avoid using Log.w() for non-warning logs in production code.",
}
# Function to search for various vulnerabilities in a Smali file and return line numbers
def find_vulnerabilities(smali_file):
    lines_with_vulnerabilities = []

    with open(smali_file, "r") as file:
        smali_code = file.readlines()

    for line_number, line in enumerate(smali_code, start=1):
        for pattern, mitigation in secret_mitigations.items():
            if re.search(pattern, line, re.IGNORECASE):
                vulnerability = (line_number, f"Potential secret '{pattern}'", mitigation)
                lines_with_vulnerabilities.append(vulnerability)

        for pattern, mitigation in insecure_storage_mitigations.items():
            if pattern in line:
                vulnerability = (line_number, f"Insecure data storage pattern '{pattern}'", mitigation)
                lines_with_vulnerabilities.append(vulnerability)

        for pattern, mitigation in code_injection_mitigations.items():
            if pattern in line:
                vulnerability = (line_number, f"Code injection pattern '{pattern}'", mitigation)
                lines_with_vulnerabilities.append(vulnerability)

        for pattern, mitigation in sensitive_data_mitigations.items():
            if pattern in line:
                vulnerability = (line_number, f"Sensitive data exposure pattern '{pattern}'", mitigation)
                lines_with_vulnerabilities.append(vulnerability)

        for pattern, mitigation in input_validation_mitigations.items():
            if pattern in line:
                vulnerability = (line_number, f"Inadequate input validation pattern '{pattern}'", mitigation)
                lines_with_vulnerabilities.append(vulnerability)

        for pattern, mitigation in exception_mitigations.items():
            if pattern in line:
                vulnerability = (line_number, f"Unhandled exception pattern '{pattern}'", mitigation)
                lines_with_vulnerabilities.append(vulnerability)

        for pattern, mitigation in insecure_communication_mitigations.items():
            if pattern in line:
                vulnerability = (line_number, f"Insecure communication pattern '{pattern}'", mitigation)
                lines_with_vulnerabilities.append(vulnerability)

        for pattern, mitigation in improper_permission_mitigations.items():
            if pattern in line:
                vulnerability = (line_number, f"Improper permission handling pattern '{pattern}'", mitigation)
                lines_with_vulnerabilities.append(vulnerability)

        for pattern, mitigation in insecure_code_execution_mitigations.items():
            if pattern in line:
                vulnerability = (line_number, f"Insecure code execution pattern '{pattern}'", mitigation)
                lines_with_vulnerabilities.append(vulnerability)

        for pattern, mitigation in broken_auth_mitigations.items():
            if pattern in line:
                vulnerability = (line_number, f"Broken authentication pattern '{pattern}'", mitigation)
                lines_with_vulnerabilities.append(vulnerability)

        for pattern, mitigation in risk_file_mitigations.items():
            if pattern in line:
                vulnerability = (line_number, f"Potentially risky files pattern '{pattern}'", mitigation)
                lines_with_vulnerabilities.append(vulnerability)

        for pattern, mitigation in code_quality_mitigations.items():
            if pattern in line:
                vulnerability = (line_number, f"Code quality pattern '{pattern}'", mitigation)
                lines_with_vulnerabilities.append(vulnerability)

    return lines_with_vulnerabilities


def decompile_apk(apk_file, app_name):
    try:
        subprocess.run(f"apktool d {apk_file} -o {app_name}", shell=True, check=True)
        print(f"APK decompiled to '{app_name}'")
        print(end="\n")
        print(f"\033[1mScanning for vulnerabilities\033[0m")
        print(end="\n")
    except subprocess.CalledProcessError as e:
        print(f"Error decompiling APK: {e}")
        exit(1)

def check_dependencies():
    # Define a list of required tools and packages
    required_tools = ["apktool"]
    required_packages = ["tabulate"]

    for tool in required_tools:
        try:
            subprocess.run([tool, "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            print(f"'{tool}' not found. Attempting to install it...")
            install_tool(tool)

    for package in required_packages:
        try:
            importlib.import_module(package)
        except ImportError:
            print(f"'{package}' not found. Attempting to install it...")
            subprocess.run([sys.executable, '-m', 'pip', 'install', package], check=True)

def install_tool(tool_name):
    if tool_name == "apktool":
        try:
            subprocess.run(["sudo", "apt-get", "install", "apktool", "-y"])
        except subprocess.CalledProcessError as e:
            print(f"Error installing '{tool_name}': {e}")
            sys.exit(1)


def main():
    print("\033[91m\033[1m\033[5m                                   AVASTA - ANDROID VULNERABILITY ASSESSMENT and SECURITY TESTING AID\033[0m")
    print(end="\n")
    print("""\033[92m
                   ╓                               ╓                                                               ╓
                  ╒╣╕                     ╣╣╣─    ╒╣╕		      ╦╣╣            ╣╣╣╣╣╣╣╣╣╣╣╣╣╣╣╣╣╣╣╣         ╒╣╕
                  ╣╣╣      ╒             ╣╣╣─  	  ╣╣╣		   ╒╣╣╩╙╣╬║╣	   ╣╣╬╣╣╬╣╣╬╣╣╬╣╣╬╣╣╬╣╣╬╣╣╬       ╣╣╣
                 ╫╣ ╫╣     ╡  ╔         ╣╣╣      ╫╣ ╫╣		   ╦╣╩   ║╣╬		     ╣╣╣╬                ╫╣ ╫╣
                ╔╣╩  ╫╣╖  ╞╬  ╣╣       ╣╣╣      ╔╣   ╫╣		   ╣╣╬    ╞╩   		      ╣╣╣╬             ╔╣╩  ╫╣
               ╔╣╣╗╗╦╦╣╣╦╦╣╣  ╣╣╣     ╣╣╣      ╔╣╣╗╗╦╦╣╣╦	    ╙╣╣╣╦╗╖		     ╣╣╣╬             ╔╣╣╗╗╦╦╣╣╦╣╞╞╣╣
              ║╣╣╜     ╫╣╖     ╣╣╣  ╒╣╣╣     ║╣╣╜     ╫╣╖		╠╜╝╣╣╣╣╗╖	      ╣╣╣╬          ║╣╣╜     ╫╣╖    ╣╣
             ╦╣╬        ╚╣╗     ╣╣╬╓╣╣╬      ╦╣╬       ╚╣╗	   ╓╦╣╣╣╩      ╙╙╝╣╣╣╗╖	     ╣╣╣╬           ╦╣╬       ╚╣╗     ╣
            ╚╣╣╖           ╙╣╣╗  ╙╣╣╣╣╩    ╚╣╣╖          ╙╣╣╗	╓╣╣╩╙ ║╣             ╙╣╣╣╖    ╣╣╣╬        ╚╣╣╖          ╙╣╣╗
    	   ╚╣╣╖╦           ╙╝╣╗╖ ╫╣╣╬     ╚╣╣╖╦          ╙╝╣╗╖	├╣╣╖    ╬           ╓╓╗╣╣╣╩  ╣╣╣╬	 ╚╣╣╖╦           ╙╝╣╗╖
       ║╣╣╣╣╣╣╣╣             ╓╣╣╣ ╣╬ ║╣╣╣╣╣╣╣╣            ╓╣╣╣ ╙╙╝╣╣╣╣╣╣╣╣╣╣╣╣╣╣╝╝╜╙╙	      ╣╣╣╬     ╣╣╣╣╣╣╣            ╓╣╣╣ 

    \033[0m""")
    print(end="\n")
    print("""\033[92m\033[1m################################################################################################################################################# 

             AVASTA - ANDROID VULNERABILITY ASSESSMENT and SECURITY TESTING AID
             By Fiyan Mehfil Ayoob , Melvina Jose , Navaneeth P
               The Vulnerabilities that are scan by this code:
                        potential secrets , insecure data storage , code injection issues , sensitive data exposure
                        inadequate input validation , unhandled exceptions , insecure communication , improper permission handling
                        insecure code execution , broken authentication , potentially risky files and code quality

#################################################################################################################################################
    \033[0m""")
    print(end="\n")
    app_name = input("Enter the name of the app (APK file) you want to scan for vulnerabilities: ")

    apk_file = app_name  # Assume the app name is the APK file name

    app_folder = os.path.splitext(os.path.basename(apk_file))[0]  # Extract app name from APK file name

    decompile_apk(apk_file, app_folder)  # Decompile the APK

    app_folder_path = os.path.join(os.getcwd(), app_folder)
    if not os.path.exists(app_folder_path):
        print(f"App folder for '{app_name}' not found.")
        return

    total_vulnerabilities = 0
    total_files = 0
    vulnerable_files = 0

    for root, dirs, files in os.walk(app_folder_path):
        for file in files:
            if file.endswith(".smali"):
                total_files += 1
                smali_file = os.path.join(root, file)
                vulnerabilities = find_vulnerabilities(smali_file)

                if vulnerabilities:
                    file_table = PrettyTable()
                    file_table.field_names = [
                        f"\033[1mLine Number\033[0m",
                        f"\033[1mDescription\033[0m",
                        f"\033[1mMitigation\033[0m",
                        f"\033[1mStatus\033[0m"
                    ]

                    for line_number, vulnerability_desc, mitigation in vulnerabilities:
                        status = f"{RED}Vulnerable{RESET}"
                        file_table.add_row([line_number, vulnerability_desc, mitigation, status])
                    print()
                    print(f"\033[1mVulnerabilities found in '{smali_file}':\033[0m")
                    print(file_table)
                    total_vulnerabilities += len(vulnerabilities)
                    vulnerable_files += 1
                    print(end="\n")

    if total_vulnerabilities == 0:
        print(f"{GREEN}\033[1mNo vulnerabilities found{RESET}")
        print(f"{GREEN}\033[1mVulnerable files: 0/{total_files} files{RESET}")
    else:
        print(f"{RED}\033[1mThe app is vulnerable with {total_vulnerabilities} vulnerabilities{RESET}")
        print(f"{RED}\033[1mVulnerable files: {vulnerable_files}/{total_files} files{RESET}")

if __name__ == "__main__":
    main()
