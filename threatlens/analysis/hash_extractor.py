import re

# MD5 hash pattern
md5_pattern = r"\b[a-fA-F0-9]{32}\b"

# SHA256 hash pattern
sha256_pattern = r"\b[a-fA-F0-9]{64}\b"


def extract_hashes(text):

    md5_hashes = re.findall(md5_pattern, text)
    sha256_hashes = re.findall(sha256_pattern, text)

    return {
        "md5": md5_hashes,
        "sha256": sha256_hashes
    }