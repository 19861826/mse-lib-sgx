"""mse_lib_sgx.cli.debug module."""

import argparse
import importlib
import logging
import sys
import sysconfig
from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from mse_lib_crypto.xsalsa20_poly1305 import decrypt_directory

from mse_lib_sgx import globs
from mse_lib_sgx.error import SecurityError
from mse_lib_sgx.certificate import DebugCertificate
from mse_lib_sgx.http_server import serve as serve_sgx_secrets


def parse_args() -> argparse.Namespace:
    """Argument parser."""
    parser = argparse.ArgumentParser(
        description="Bootstrap ASGI/WSGI Python web application for Gramine"
    )
    parser.add_argument(
        "application",
        type=str,
        help="Application to dispatch to as path.to.module:instance.path",
    )
    parser.add_argument(
        "--app-dir",
        required=True,
        type=Path,
        help="Path of the microservice application. Read only directory.",
    )

    return parser.parse_args()


def run() -> None:
    """Entrypoint of the CLI debugger."""
    args: argparse.Namespace = parse_args()

    globs.HOME_DIR_PATH.mkdir(exist_ok=True)
    globs.KEY_DIR_PATH.mkdir(exist_ok=True)
    globs.MODULE_DIR_PATH.mkdir(exist_ok=True)

    logging.basicConfig(
        level=logging.DEBUG, format="[%(asctime)s] [%(levelname)s] %(message)s"
    )

    expiration_date = datetime.now() + timedelta(hours=10)

    logging.info("Generating the self signed certificate...")

    subject: x509.Name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Ile-de-France"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Paris"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cosmian Tech"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )

    cert: DebugCertificate = DebugCertificate(
        dns_name="localhost",
        subject=subject,
        root_path=globs.KEY_DIR_PATH,
        expiration_date=expiration_date,
    )

    logging.info("Starting the configuration server...")

    serve_sgx_secrets(
        hostname="0.0.0.0",
        port=8080,
        certificate=cert,
        uuid="00000000-0000-0000-0000-000000000000",
        need_ssl_private_key=False,
    )

    if globs.CODE_SECRET_KEY:
        logging.info("Decrypting code...")
        decrypt_directory(
            dir_path=args.app_dir,
            key=globs.CODE_SECRET_KEY,
            ext=".enc",
            out_dir_path=globs.MODULE_DIR_PATH,
        )
        (globs.KEY_DIR_PATH / "code.key").write_bytes(globs.CODE_SECRET_KEY)
    else:
        logging.error("Configuration server stopped and no secret key provided")
        raise SecurityError("Code secret key not provided")

    logging.info("Loading the application...")
    module_name, application_name = args.application.split(":")

    sys.path.append(f"{globs.MODULE_DIR_PATH.resolve()}")

    logging.debug("MODULE_PATH=%s", globs.MODULE_DIR_PATH)
    logging.debug("sys.path: %s", sys.path)
    logging.debug("sysconfig.get_paths(): %s", sysconfig.get_paths())
    logging.debug("application: %s", args.application)

    module = importlib.import_module(module_name)
    logging.info("%s", dir(module))

    application = getattr(module, application_name)

    logging.info("%s:%s: %s", module_name, application_name, application)
