# Configuration
#
# We have numerous things that could be configured, but since this is
# just a demonstration, we wil hard code as just constants in this
# file.  These are intended to match the names used by the
# implementation, when that makes sense.

from pathlib import Path

cert_dir = Path("certs")

def ca_cert():
    return cert_dir / "CA.crt"

def ca_key():
    return cert_dir / "CA.key"

def device_cert(dev_id):
    return cert_dir / (dev_id + ".crt")

def device_key(dev_id):
    return cert_dir / (dev_id + ".key")
