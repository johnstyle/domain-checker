import OpenSSL
import ssl
import requests
import socket
import re
from urlparse import urlparse
from datetime import datetime


def header():
    return [
        'Domain',
        'RealDomain',
        'SubjectCN',
        'SubjectAltName',
        'HttpsEnabled',
        'HttpsValid',
        'HttpsTrueHost',
        'HttpsValidDate',
        'HttpsRedirection',
        'CreatedAt',
        'ExpireAt',
        'IssuerO',
        'IssuerOU',
        'IssuerCN',
        'EmailAddress',
        'OrganizationName',
        'SignatureAlgorithm',
        'Version',
        'KeyBits',
        'KeyType',
        'SerialNumber'
    ]


def check(domain):
    print(domain)

    http_url = requests.head('http://' + domain, timeout=5, allow_redirects=True).url
    https_url = requests.head('https://' + domain, timeout=5, allow_redirects=True).url
    http_uri = urlparse(http_url)
    https_uri = urlparse(https_url)

    real_domain = https_uri.netloc
    https_enabled = 'https' == https_uri.scheme
    subject_alt_name = ''

    try:
        conn = ssl.create_connection((real_domain, 443))
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        sock = context.wrap_socket(conn, server_hostname=real_domain)
        cert = ssl.DER_cert_to_PEM_cert(sock.getpeercert(True))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

        https_valid = 1
        https_redirection = https_enabled and http_uri.scheme == https_uri.scheme and http_uri.netloc == https_uri.netloc

        created_at = datetime.strptime(x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ').strftime('%Y-%m-%d %H:%M:%S')
        expire_at = datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ').strftime('%Y-%m-%d %H:%M:%S')
        subject_cn = x509.get_subject().CN
        subject_organization_name = x509.get_subject().organizationName
        issuer_o = x509.get_issuer().O
        issuer_ou = x509.get_issuer().OU
        issuer_cn = x509.get_issuer().CN
        issuer_email_address = x509.get_issuer().emailAddress
        signature_algorithm = x509.get_signature_algorithm()
        version = x509.get_version()
        pubkey_bits = x509.get_pubkey().bits()
        pubkey_type = x509.get_pubkey().type()

        for i in xrange(x509.get_extension_count()):
            if 'subjectAltName' == x509.get_extension(i).get_short_name():
                subject_alt_name = str(x509.get_extension(i))

        true_host = re.sub(r"^(?:[a-zA-Z0-9\-\.]+\.)?([a-zA-Z0-9\-]+\.[a-zA-Z0-9]+)$", r"\1", real_domain)
        regex = re.compile(r"DNS:(\\*\.)?" + re.sub(r"\.", "\\.", true_host) + "(,.+|$)")
        https_true_host = true_host == subject_cn or None is not regex.search(subject_alt_name)

        https_valid_date = not x509.has_expired()
        serial_number = x509.get_serial_number()

    except socket.error:
        https_enabled = 0
        https_valid = 0
        https_redirection = 0
        https_true_host = 0
        https_valid_date = 0
        created_at = ''
        expire_at = ''
        subject_cn = ''
        issuer_o = ''
        issuer_ou = ''
        issuer_cn = ''
        issuer_email_address = ''
        subject_organization_name = ''
        signature_algorithm = ''
        version = ''
        pubkey_bits = ''
        pubkey_type = ''
        serial_number = ''

    return [
        str(domain),
        str(real_domain),
        str(subject_cn),
        str(subject_alt_name),
        int(https_enabled),
        int(https_valid),
        int(https_true_host),
        int(https_valid_date),
        int(https_redirection),
        str(created_at),
        str(expire_at),
        str(issuer_o),
        str(issuer_ou),
        str(issuer_cn),
        str(issuer_email_address),
        str(subject_organization_name),
        str(signature_algorithm),
        str(version),
        str(pubkey_bits),
        str(pubkey_type),
        str(serial_number)
    ]
