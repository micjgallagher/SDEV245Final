from __future__ import annotations

import argparse
import re
import os

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
        ],

        SecretType.TOKEN: [
            "^ ghp_[a - zA - Z0 - 9]{36}$",  #Github Token
            "^ ghu_[a - zA - Z0 - 9]{36}$", #Github User to server access token
            "[0 - 9a - f]{32} - us[0 - 9]{1, 2}" #Mailchimp access token
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
    lines = text.splitlines()

    for line_num, line in enumerate(lines):
        result = detect_string_constant_secret(line)
        if result is not None:
            output = f"Detected {result.name} on line {line_num} : {line}"
            detected_lines.append(output)
    return detected_lines

def scan_file(filename):
    print()
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

def scan_path(path, recurse = False):
    print()
    if os.path.isdir(path):
        print("Scanning directory", path)
        dir_contents = os.listdir(path)
        for item in dir_contents:
            item_path = os.path.join(path, item)
            if recurse and os.path.isdir(item_path):
                scan_path(item_path)
            elif os.path.isfile(item_path):
                scan_file(item_path)

    elif os.path.isfile(path):
        scan_file(path)
    else:
        print("ERROR INVALID PATH")


def main():
    parser = argparse.ArgumentParser()
    # parser.add_argument("help")
    parser.add_argument("path", help="Path tool will search for sercrets")
    parser.add_argument("-r", "--recurse", help = "Check subdirectories", action="store_true")
    args = parser.parse_args() #This line can
    # print(args.echo)
    scan_path(args.path, recurse=args.recurse)


if __name__ == '__main__':
    main()

