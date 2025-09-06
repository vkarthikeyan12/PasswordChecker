import re
import math
import requests


# Function to calculate entropy (password randomness measure)
def calculate_entropy(password):
    pool = 0
    if re.search(r'[a-z]', password):
        pool += 26
    if re.search(r'[A-Z]', password):
        pool += 26
    if re.search(r'[0-9]', password):
        pool += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        pool += 32
    if pool == 0:
        return 0
    entropy = len(password) * math.log2(pool)
    return entropy


# Function to check if password is leaked using HaveIBeenPwned API
def is_pwned(password):
    import hashlib
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    if suffix in response.text:
        return True
    return False


# Function to evaluate password strength
def check_password_strength(password):
    length_error = len(password) < 8
    lowercase_error = re.search(r"[a-z]", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    digit_error = re.search(r"[0-9]", password) is None
    symbol_error = re.search(r"[^a-zA-Z0-9]", password) is None

    errors = {
        "Too short (<8 chars)": length_error,
        "Missing lowercase letter": lowercase_error,
        "Missing uppercase letter": uppercase_error,
        "Missing digit": digit_error,
        "Missing special character": symbol_error,
    }

    failed = [msg for msg, err in errors.items() if err]

    entropy = calculate_entropy(password)
    pwned = is_pwned(password)

    print("\n🔐 Password Analysis:")
    if failed:
        print("❌ Weaknesses found:")
        for f in failed:
            print("   -", f)
    else:
        print("✅ Meets basic complexity rules")

    print(f"🔢 Entropy Score: {entropy:.2f} bits")

    if entropy < 28:
        print("⚠️ Strength: Very Weak")
    elif entropy < 36:
        print("⚠️ Strength: Weak")
    elif entropy < 60:
        print("✅ Strength: Reasonable")
    elif entropy < 128:
        print("✅ Strength: Strong")
    else:
        print("✅💪 Strength: Very Strong")

    if pwned:
        print("🚨 This password has appeared in known breaches! Avoid using it.")
    else:
        print("✅ This password was not found in known breaches.")


# Main program
if __name__ == "__main__":
    pwd = input("Enter a password to check: ")
    check_password_strength(pwd)
