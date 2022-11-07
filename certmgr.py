#!/usr/bin/python3
import argparse
import os
from OpenSSL import crypto
from subprocess import check_output
from tabulate import tabulate
import datetime
import sys


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


ovpn_cfg_info = '''
client
dev tun
proto tcp-client
remote $server_info
resolv-retry infinite
nobind
float
ncp-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC:AES-128-CBC
keepalive 15 60
auth-user-pass
remote-cert-tls server

<ca>
$ca_file_content
</ca>
<cert>
$crt_file_content

</cert>
<key>
$private_key_content

</key>
'''


def get_pki_path():
    res = check_output(['easyrsa'])
    for _line in res.splitlines():
        line = _line.decode('utf-8').strip()
        if line.startswith('PKI: '):
            bug_workaround = line.split('PKI: ')[1]
            if bug_workaround.startswith('//'):
                return bug_workaround[1:]
            return line.split(" ")[1]


def get_cert_info(cert_path):
    try:
        cert_file = open(cert_path).read()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file)
        return {
            'serial': cert.get_serial_number(),
            'not_before': cert.get_notBefore().decode('utf-8'),
            'not_after': cert.get_notAfter().decode('utf-8'),
            'subject': cert.get_subject().CN,
            'issuer': cert.get_issuer().CN,
            'fingerprint': cert.digest('sha1').decode('utf-8'),
            'path': cert_path,
            'has_expired': cert.has_expired()
        }
    except FileNotFoundError:
        raise FileNotFoundError('File not found: {}'.format(cert_path))
    except IOError:
        raise IOError('File not readable: {}'.format(cert_path))


parser = argparse.ArgumentParser(
    description='OpenVPN Client Certificate Manager')
parser.add_argument('--list-issued', dest='list_issued',
                    action='store_true', help='List all issued certificates')
parser.add_argument('--list-revoked', dest='list_revoked',
                    action='store_true', help='List all revoked certificates')
parser.add_argument('--issue', dest='issue',
                    action='store_true', help='Issue a certificate')
parser.add_argument('--generate-openvpn-config', dest='generate_openvpn_config',
                    action='store_true', help='Generate OpenVPN config file')
parser.add_argument('--server-info', dest='server_info',
                    help='Server info for OpenVPN config file', default='example.com 1194')
parser.add_argument('--revoke', action='store_true',
                    dest='revoke', help='Revoke a certificate')
parser.add_argument('--name', dest='name', help='Name of the certificate')
parser.add_argument('--days', dest='days', type=int,
                    help='Number of days the certificate is valid')

args = parser.parse_args()

args = parser.parse_args()
pki_path = get_pki_path()

if args.list_issued:
    cert_path = pki_path + '/issued'
    certs = []
    for _cert in os.listdir(cert_path):
        try:
            cert = get_cert_info(cert_path + '/' + _cert)
            certs.append([
                cert['issuer'],
                cert['subject'],
                datetime.datetime.strptime(
                    cert['not_before'], '%Y%m%d%H%M%SZ'),
                datetime.datetime.strptime(
                    cert['not_before'], '%Y%m%d%H%M%SZ'),
                cert['fingerprint'],
                cert['has_expired'] and 'Expired' or 'Valid',
            ])
        except Exception as e:
            eprint(f"Error while parsing certificate:", e)
    print(tabulate(certs, headers=[
          'Issuer', 'Owner', 'Not Before', 'Not After',  'Hash', 'Status']))
    exit(0)

if args.issue:
    if args.name is None:
        eprint('You must provide a name for the certificate')
        exit(1)
    if args.days is None:
        eprint('You must provide the number of days the certificate is valid')
        exit(1)
    os.system(
        f'EASYRSA_BATCH=yes EASYRSA_CERT_EXPIRE={args.days} easyrsa build-client-full {args.name} nopass')
    exit(0)

if args.generate_openvpn_config:
    if args.name is None:
        print('You must provide a name for the certificate')
        exit(1)
    ca_cert_path = pki_path + '/ca.crt'
    client_cert_path = pki_path + '/issued/' + args.name + '.crt'
    client_key_path = pki_path + '/private/' + args.name + '.key'
    exists = [
        os.path.exists(ca_cert_path),
        os.path.exists(client_cert_path),
        os.path.exists(client_key_path),
    ]
    if not all(exists):
        exists = [not x for x in exists]
        eprint('The following files are missing:')
        eprint(ca_cert_path if exists[0] else '')
        eprint(client_cert_path if exists[1] else '')
        eprint(client_key_path if exists[2] else '')
        eprint('\nPlease make sure you have issued the certificate')
        exit(1)
    ca_cert = open(ca_cert_path).read()

    client_cert_content = f'''-----BEGIN CERTIFICATE-----{open(client_cert_path).read().split('-----BEGIN CERTIFICATE-----')[1].split('-----END CERTIFICATE-----')[0]}-----END CERTIFICATE-----'''

    client_key_content = f'''-----BEGIN PRIVATE KEY-----{open(client_key_path).read().split('-----BEGIN PRIVATE KEY-----')[1].split('-----END PRIVATE KEY-----')[0]}-----END PRIVATE KEY-----'''

    ovpn_cfg = ovpn_cfg_info.replace('$server_info', args.server_info).replace('$ca_file_content', ca_cert).replace(
        '$crt_file_content', client_cert_content).replace('$private_key_content', client_key_content)
    print(ovpn_cfg)
    # open(args.name + '.ovpn', 'w').write(ovpn_cfg)
    # print(f'OpenVPN config file generated in {args.name}.ovpn')
    exit(0)

if args.list_revoked:
    crl_path = pki_path + '/crl.pem'
    if not os.path.exists(crl_path):
        eprint('Initializing CRL...')
        os.system('easyrsa gen-crl')
        exit(0)
    crl = crypto.load_crl(crypto.FILETYPE_PEM, open(crl_path).read())
    revoked = []
    if crl.get_revoked() is None:
        eprint('No revoked certificates')
        exit(0)
    for _revoked in crl.get_revoked():
        revoked_cert_info = get_cert_info(
            pki_path + '/revoked/certs_by_serial/' + _revoked.get_serial().decode('utf-8') + '.crt')
        revoked.append([
            _revoked.get_serial(),
            revoked_cert_info['issuer'],
            revoked_cert_info['subject'],
            datetime.datetime.strptime(
                revoked_cert_info['not_before'], '%Y%m%d%H%M%SZ'),
            revoked_cert_info['fingerprint'],
            datetime.datetime.strptime(
                _revoked.get_rev_date().decode('utf-8'), '%Y%m%d%H%M%SZ'),
        ])
    print(tabulate(revoked, headers=[
          'Revoke Serial', 'Issuer', 'Owner', 'Issue Date', 'Cert Fingerprint', 'Revocation Date']))
    exit(0)

if args.revoke:
    if args.name is None:
        eprint('You must provide a name for the certificate')
        exit(1)
    os.system(f'EASYRSA_BATCH=yes easyrsa revoke {args.name}')
    os.system(f'EASYRSA_BATCH=yes easyrsa gen-crl')
    exit(0)

parser.print_help()
