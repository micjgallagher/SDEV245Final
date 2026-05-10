from __future__ import annotations

import re

from enum import Enum, auto

class SecretType(Enum):
    API_KEY = auto()
    PASSWORD = auto()
    TOKEN = auto()
    PRIVATE_KEY = auto()


def detect_string_constant_secret(line: str) -> SecretType | None:
    """
    Scans a line of text for secrets strictly hardcoded as string constants.
    Supports multiple distinct regex patterns for each secret type.
    """

    # Dictionary mapping the Enum to a LIST of Regex patterns
    patterns = {
        SecretType.PRIVATE_KEY: [
            r"['\"\`]-----BEGIN RSA PRIVATE KEY-----.*?['\"\`]",  # RSA
            r"['\"\`]-----BEGIN OPENSSH PRIVATE KEY-----.*?['\"\`]"  # OpenSSH
        ],

        SecretType.API_KEY: [
            r"['\"\`]AKIA[0-9A-Z]{16}['\"\`]",  # AWS Access Key ID
            r"['\"\`]AIza[0-9A-Za-z\-_]{35}['\"\`]",  # Google Cloud API Key
            r"(?i)(api[_\-]?key)[\s]*[:=][\s]*['\"\`][a-zA-Z0-9_\-]{10,}['\"\`]"  # Generic API key assignment
        ],

        SecretType.TOKEN: [
            r"['\"\`]gh[pousr]_[a-zA-Z0-9]{36}['\"\`]",  # GitHub Token
            r"['\"\`]xox[baprs]-[0-9a-zA-Z\-]+['\"\`]",  # Slack Token
            r"(?i)(token|bearer)[\s]*[:=][\s]*['\"\`][a-zA-Z0-9_\-\.]+['\"\`]"  # Generic token assignment
        ],

        SecretType.PASSWORD: [
            r"(?i)(password|passwd|pwd)[\s]*[:=][\s]*['\"\`][^'\"\`]{4,}['\"\`]"  # Generic password assignment
        ]
    }

    for secret_type, pattern_list in patterns.items():
        for pattern in pattern_list:
            if re.search(pattern, line):
                return secret_type

    return None


def scan(text : str):
    #Returns array of strings as output

    detected_lines = []
    lines = text.split()

    for line_num, line in enumerate(lines):
        result = detect_string_constant_secret(line)
        if result is not None:
            output = f"Detected {result.name} on line {line_num} : {line}"
            detected_lines.append(output)
    return detected_lines

def scan_file(filename):
    try:
        with open(filename) as file:
            content = file.read()

            detected_lines = scan(content)

            print("Scanning", filename)
            if len(detected_lines) > 0:
                for line in detected_lines:
                    print(line)
            else:
                print("No Hardcoded Secrets detected")
    except FileNotFoundError:
        print(filename, "does not exist")



def main():
    scan_file("example.txt")


if __name__ == '__main__':
    main()

