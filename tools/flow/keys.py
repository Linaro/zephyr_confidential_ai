# Key management

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
import datetime
import uuid

import config

class CA():
    """Manage the CA."""
    def __init__(self):
        self.private = None
        self.public = None

    def gen(self):
        """Generate a new certificate.

        This will discard any existing certificates managed by this
        object, building one.  The CA will have a public and private
        key available.  As of now, none of the parameters can be set.
        This is intended for demo purposes.
        """
        priv = ec.generate_private_key(ec.SECP256R1)
        #save_key(priv)

        builder = x509.CertificateBuilder()
        myname = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'Flow test CA'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Linaro Ltd'),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'Special CA'),
            ])
        builder = builder.subject_name(myname)
        builder = builder.issuer_name(myname)
        builder = builder.not_valid_before(datetime.datetime.today())
        builder = builder.not_valid_after(datetime.datetime.today() + datetime.timedelta(3650))
        builder = builder.serial_number(int(uuid.uuid4()))
        builder = builder.public_key(priv.public_key())
        builder = builder.add_extension(
                # Ugh, lovely API. Certificate signing is the 6th
                # argument.
                x509.KeyUsage(False, False, False, False, False, True, False, False, False),
                critical=True)
        builder = builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True,
                )
        builder = builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(priv.public_key()), critical=False)
        builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(priv.public_key()), critical=False)

        cert = builder.sign(
                private_key=priv, algorithm=hashes.SHA256(),
                backend=default_backend())

        self.private = priv
        self.public = priv.public_key()
        self.cert = cert

    def save(self, keypath, certpath):
        """
        Save both the private key and the certificate to files of the given names.
        """
        self.save_key(keypath)
        self.save_cert(certpath)

    def save_key(self, keypath):
        """
        Write the private key for use by the certificate authority.

        This is in
        "openssl" format, and can be examined with:
            openssl ec -in certs/CA.key -noout -text
        or
            openssl asn1parse -in certs/CA.key -inform PEM

        In this case: the key will be something like (with obviously a
        different actual key)

           0:d=0  hl=2 l= 119 cons: SEQUENCE
           2:d=1  hl=2 l=   1 prim:  INTEGER           :01
           5:d=1  hl=2 l=  32 prim:  OCTET STRING      [HEX DUMP]:461D9FDBEBF0628161BE0FDB6AC23FF533E25E841938A89A78B355D46F08ECB3
          39:d=1  hl=2 l=  10 cons:  cont [ 0 ]
          41:d=2  hl=2 l=   8 prim:   OBJECT            :prime256v1
          51:d=1  hl=2 l=  68 cons:  cont [ 1 ]
          53:d=2  hl=2 l=  66 prim:   BIT STRING

        Note that the private key file does not contain the public key,
        although it will be printed out if requested by the 'ec' command (as
        it can easily be generated).
        """
        enc_priv = self.private.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption())
        with open(keypath, "wb") as fd:
            fd.write(enc_priv)

    def save_cert(self, certpath):
        with open(certpath, "wb") as fd:
            fd.write(self.cert.public_bytes(
                encoding=serialization.Encoding.PEM))
