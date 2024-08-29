#!/usr/bin/env python3

import json
import logging
import os
import sys
from cryptography import x509
from cryptography.hazmat.primitives.serialization import \
    BestAvailableEncryption, load_pem_private_key, pkcs12
from urllib import request

# https://porkbun.com/api/json/v3/documentation
DEFAULT_API_URL = "https://porkbun.com/api/json/v3"
DEFAULT_CERTIFICATE_PATH = "/etc/porkcron/certificate.crt"
DEFAULT_PRIVATE_KEY_PATH = "/etc/porkcron/private_key.key"
DEFAULT_PKCS12_PATH = "/etc/porkcron/pkcs12.p12"
DEFAULT_PKCS12_FRIENDLY_NAME = "porkcron"


def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")
    logging.info("running SSL certificate renewal script")

    domain = getenv_or_exit("DOMAIN")
    api_key = getenv_or_exit("API_KEY")
    secret_key = getenv_or_exit("SECRET_KEY")

    url = os.getenv("API_URL", DEFAULT_API_URL) + "/ssl/retrieve/" + domain
    body = json.dumps({"apikey": api_key, "secretapikey": secret_key}).encode()
    headers = {"Content-Type": "application/json"}

    logging.info(f"downloading SSL bundle for {domain}")
    req = request.Request(url, data=body, headers=headers, method="POST")
    with request.urlopen(req) as resp:
        data = json.load(resp)

    if data["status"] == "ERROR":
        logging.error(data["message"])
        sys.exit(1)

    certificate_path = os.getenv("CERTIFICATE_PATH", DEFAULT_CERTIFICATE_PATH)
    logging.info(f"saving certificate to {certificate_path}")
    with open(certificate_path, "w") as f:
        f.write(data["certificatechain"])

    private_key_path = os.getenv("PRIVATE_KEY_PATH", DEFAULT_PRIVATE_KEY_PATH)
    logging.info(f"saving private key to {private_key_path}")
    with open(private_key_path, "w") as f:
        f.write(data["privatekey"])

    pkcs12_password = os.getenv("PKCS12_PASSWORD")
    if pkcs12_password is not None:
        pkcs12_path = os.getenv("PKCS12_PATH", DEFAULT_PKCS12_PATH)
        friendly_name = os.getenv(
            "PKCS12_FRIENDLY_NAME", DEFAULT_PKCS12_FRIENDLY_NAME)
        cert = x509.load_pem_x509_certificate(
            data["certificatechain"].encode())
        key = load_pem_private_key(data["privatekey"].encode(), None)
        p12 = pkcs12.serialize_key_and_certificates(
            friendly_name.encode(), key, cert, None,
            BestAvailableEncryption(pkcs12_password.encode())
        )
        logging.info(f"saving PKCS #12 blob to {pkcs12_path}")
        with open(pkcs12_path, "wb") as f:
            f.write(p12)

    logging.info("SSL certificate has been successfully renewed")


def getenv_or_exit(key: str) -> str:
    value = os.getenv(key)
    if value is not None:
        return value

    logging.error(f"{key} is required but not set")
    sys.exit(1)


if __name__ == "__main__":
    main()
