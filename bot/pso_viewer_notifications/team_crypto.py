"""PSO1 interoperability via the installed OpenSSL, Python 3.7+.

No cryptographic primitive is implemented here. DER helpers only validate key
encoding and convert OpenSSL's ECDSA signature to WebCrypto's 64-byte format.
Private keys and patient text are never passed in command-line arguments.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import unicodedata

DOMAIN = 'PSO-SURNAME-LINK-v1'
CARD_DOMAIN = 'PSO-CONTACT-v1'
TEAM_DOMAIN = 'PSO-TEAM-v1\0'
RSA_ALGORITHM = bytes.fromhex('300d06092a864886f70d0101010500')
EC_ALGORITHM = bytes.fromhex('301306072a8648ce3d020106082a8648ce3d030107')


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


def b64(value):
    return base64.urlsafe_b64encode(value).decode('ascii').rstrip('=')


def unb64(value, size=None, maximum=5000):
    if not isinstance(value, str) or not 0 < len(value) <= maximum or not re.fullmatch(r'[A-Za-z0-9_-]+', value):
        raise ValueError('Некорректный код.')
    raw = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    if b64(raw) != value or (size is not None and len(raw) != size):
        raise ValueError('Некорректный код.')
    return raw


def tlv(data, offset=0, tag=None):
    if offset + 2 > len(data):
        raise ValueError('Некорректная структура ключа.')
    actual, length = data[offset], data[offset + 1]
    start = offset + 2
    if tag is not None and actual != tag:
        raise ValueError('Некорректная структура ключа.')
    if length & 128:
        count = length & 127
        if not 1 <= count <= 4 or start + count > len(data) or data[start] == 0:
            raise ValueError('Некорректная длина ключа.')
        length = int.from_bytes(data[start:start + count], 'big')
        if length < 128:
            raise ValueError('Неканоническая длина ключа.')
        start += count
    end = start + length
    if end > len(data):
        raise ValueError('Ключ обрезан.')
    return data[start:end], end


def integer(raw):
    if not raw or raw[0] & 128 or (len(raw) > 1 and raw[0] == 0 and not raw[1] & 128):
        raise ValueError('Некорректное целое в ключе.')
    return int.from_bytes(raw, 'big')


def validate_spki(rsa, ec):
    body, end = tlv(rsa, tag=48)
    if end != len(rsa) or not body.startswith(RSA_ALGORITHM):
        raise ValueError('Ожидается RSA 3072.')
    bits, end = tlv(body, len(RSA_ALGORITHM), 3)
    if end != len(body) or not bits or bits[0] != 0:
        raise ValueError('Некорректный RSA ключ.')
    numbers, end = tlv(bits[1:], tag=48)
    if end != len(bits) - 1:
        raise ValueError('Некорректный RSA ключ.')
    modulus, pos = tlv(numbers, tag=2)
    exponent, pos = tlv(numbers, pos, 2)
    if pos != len(numbers) or integer(modulus).bit_length() != 3072 or integer(exponent) != 65537:
        raise ValueError('Ожидается RSA 3072 с экспонентой 65537.')
    body, end = tlv(ec, tag=48)
    if end != len(ec) or not body.startswith(EC_ALGORITHM):
        raise ValueError('Ожидается ключ P-256.')
    bits, end = tlv(body, len(EC_ALGORITHM), 3)
    if end != len(body) or len(bits) != 66 or bits[:2] != b'\0\x04':
        raise ValueError('Некорректный ключ P-256.')


def der_to_raw(signature):
    body, end = tlv(signature, tag=48)
    if end != len(signature):
        raise ValueError('Некорректная подпись.')
    r, pos = tlv(body, tag=2)
    s, pos = tlv(body, pos, 2)
    r, s = integer(r), integer(s)
    if pos != len(body) or not 0 < r < 2 ** 256 or not 0 < s < 2 ** 256:
        raise ValueError('Некорректная подпись.')
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')


def raw_to_der(signature):
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise ValueError('Некорректная подпись.')
    values = []
    for half in (signature[:32], signature[32:]):
        value = half.lstrip(b'\0') or b'\0'
        if value[0] & 128:
            value = b'\0' + value
        values.append(b'\x02' + bytes([len(value)]) + value)
    body = b''.join(values)
    return b'\x30' + bytes([len(body)]) + body


def read_card(value):
    if not isinstance(value, str) or not value.startswith('PSO-CARD1.') or len(value) > 5000:
        raise ValueError('Некорректная карточка устройства.')
    text = unb64(value[10:]).decode('utf-8')
    obj = json.loads(text)
    if not isinstance(obj, dict) or set(obj) != {'v', 'n', 'e', 's'} or obj['v'] != 1 or compact(obj) != text:
        raise ValueError('Некорректная карточка устройства.')
    name = obj['n']
    if not isinstance(name, str) or not 1 <= len(name) <= 60 or name.strip() != name or unicodedata.normalize('NFC', name) != name or any(unicodedata.category(c) in ('Cc', 'Cf') for c in name):
        raise ValueError('Некорректное имя устройства.')
    rsa, ec = unb64(obj['e'], maximum=1000), unb64(obj['s'], maximum=300)
    validate_spki(rsa, ec)
    identity = b64(hashlib.sha256((CARD_DOMAIN + '\0' + obj['e'] + '\0' + obj['s']).encode('utf-8')).digest())
    return {'id': identity, 'name': name, 'rsa': rsa, 'ec': ec, 'card': value}


def surname_value(value):
    if not isinstance(value, str) or any(unicodedata.category(c) in ('Cc', 'Cf') for c in value):
        raise ValueError('Не удалось подготовить фамилию к шифрованию.')
    value = re.sub(' +', ' ', unicodedata.normalize('NFC', value).strip()).replace('\u2010', '-').replace('\u2011', '-')
    previous_letter = False
    for c in value:
        category = unicodedata.category(c)
        if category.startswith('L') and ('LATIN' in unicodedata.name(c, '') or 'CYRILLIC' in unicodedata.name(c, '')):
            previous_letter = True
        elif category.startswith('M') and previous_letter:
            pass
        elif c in " '-\u2019\u02bc" and previous_letter:
            previous_letter = False
        else:
            raise ValueError('Не удалось подготовить фамилию к шифрованию.')
    if not previous_letter or not 1 <= len(value) <= 80:
        raise ValueError('Не удалось подготовить фамилию к шифрованию.')
    return value


class OpenSSLIdentity:
    def __init__(self, directory, create=False, binary=None):
        self.directory = Path(directory)
        self.binary = binary or shutil.which('openssl')
        if not self.binary:
            raise RuntimeError('OpenSSL не найден. Шифрование недоступно; сообщения не отправляются.')
        self.rsa_file, self.sign_file = self.directory / 'bot_rsa.pem', self.directory / 'bot_sign.pem'
        if self.directory.is_symlink():
            raise RuntimeError('Папка ключей не должна быть ссылкой.')
        if create:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(str(self.directory), 0o700)
            existing = [p.exists() for p in (self.rsa_file, self.sign_file)]
            if any(existing) and not all(existing):
                raise RuntimeError('Неполный набор ключей бота. Не удаляйте ключи; требуется восстановление.')
            if not any(existing):
                rsa = self.run(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072'])
                ec = self.run(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256'])
                for path, content in ((self.rsa_file, rsa), (self.sign_file, ec)):
                    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, 'wb') as f:
                        f.write(content)
                        f.flush()
                        os.fsync(f.fileno())
        for path in (self.rsa_file, self.sign_file):
            if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
                raise RuntimeError('Ключи бота отсутствуют или доступны другим пользователям. Выполните подключение шифрования.')
        rsa = self.run(['pkey', '-in', str(self.rsa_file), '-pubout', '-outform', 'DER'])
        ec = self.run(['pkey', '-in', str(self.sign_file), '-pubout', '-outform', 'DER'])
        validate_spki(rsa, ec)
        self.card = 'PSO-CARD1.' + b64(compact({'v': 1, 'n': 'Устройство', 'e': b64(rsa), 's': b64(ec)}).encode('utf-8'))
        self.id = read_card(self.card)['id']

    def run(self, args, data=None):
        try:
            result = subprocess.run([self.binary] + args, input=data, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise RuntimeError('OpenSSL не выполнил операцию. Отправка остановлена.') from None
        if result.returncode:
            raise RuntimeError('OpenSSL не выполнил операцию. Отправка остановлена.')
        return result.stdout

    def sign(self, value):
        return der_to_raw(self.run(['dgst', '-sha256', '-sign', str(self.sign_file)], value))

    def verify_signature(self, public_der, signature, message):
        # Temporary files contain only a public signing key and a signature.
        # Signed bytes are sent through stdin, never command-line arguments.
        import tempfile
        with tempfile.TemporaryDirectory(prefix='pso-verify-', dir=str(self.directory)) as folder:
            key = Path(folder) / 'issuer.pem'
            sig = Path(folder) / 'signature.der'
            key.write_bytes(self.run(['pkey', '-pubin', '-inform', 'DER', '-outform', 'PEM'], public_der))
            sig.write_bytes(raw_to_der(signature))
            self.run(['dgst', '-sha256', '-verify', str(key), '-signature', str(sig)], message)
        return True

    def envelope(self, op, data, issued):
        obj = {'v': 1, 'op': op, 'issued': issued, 'nonce': b64(os.urandom(16)), 'card': self.card, 'data': data}
        obj['signature'] = b64(self.sign((TEAM_DOMAIN + compact(obj)).encode('utf-8')))
        return obj

    def seal(self, contact, surname, department, issued, expires):
        card = read_card(contact['card'])
        if contact['id'] != card['id'] or department not in ('', 'ПСО', 'ОРИТ') or not 60000 <= expires - issued <= 86400000:
            raise ValueError('Не удалось проверить получателя или срок ссылки.')
        payload = {'n': surname_value(surname), 'd': department, 'j': b64(os.urandom(12)), 'i': issued, 'x': expires}
        plain = compact(payload).encode('utf-8')
        if len(plain) > 318:
            raise ValueError('Фамилия превышает допустимую длину зашифрованной записи.')
        # Public key file only; no patient text or private key is placed in temp files.
        import tempfile
        with tempfile.TemporaryDirectory(prefix='pso-public-', dir=str(self.directory)) as folder:
            public = Path(folder) / 'recipient.der'
            public.write_bytes(card['rsa'])
            encrypted = self.run(['pkeyutl', '-encrypt', '-pubin', '-keyform', 'DER', '-inkey', str(public),
                                  '-pkeyopt', 'rsa_padding_mode:oaep', '-pkeyopt', 'rsa_oaep_md:sha256',
                                  '-pkeyopt', 'rsa_mgf1_md:sha256', '-pkeyopt', 'rsa_oaep_label:' + DOMAIN.encode().hex()], plain)
        if len(encrypted) != 384:
            raise RuntimeError('Шифрование вернуло неверный размер записи.')
        prefix = 'PSO1.' + card['id'] + '.' + self.id + '.' + b64(encrypted)
        return prefix + '.' + b64(self.sign((DOMAIN + '\0' + prefix).encode('utf-8')))
