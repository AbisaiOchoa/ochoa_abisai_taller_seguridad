"""Cadena simétrica de claves de mensaje basada en HKDF y AES-GCM."""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_LONGITUD_CLAVE = 32
_LONGITUD_NONCE = 12
_LONGITUD_TAG = 16


def derivar_clave(cadena: bytes, indice: int) -> bytes:
    """Deriva de forma determinista una clave AES-256 para un índice."""
    if not isinstance(cadena, bytes) or not cadena:
        raise ValueError("La cadena debe ser bytes y no estar vacía.")
    if isinstance(indice, bool) or not isinstance(indice, int) or indice < 0:
        raise ValueError("El índice debe ser un entero no negativo.")

    return HKDF(
        algorithm=SHA256(),
        length=_LONGITUD_CLAVE,
        salt=None,
        info=b"taller-messenger/a1/message-key/v1/" + indice.to_bytes(8, "big"),
    ).derive(cadena)


def cifrar(clave: bytes, texto: str, aad: bytes = b"") -> bytes:
    """Cifra texto UTF-8 con AES-256-GCM y devuelve nonce seguido del cifrado."""
    if not isinstance(clave, bytes) or len(clave) != _LONGITUD_CLAVE:
        raise ValueError("La clave debe tener exactamente 32 bytes.")
    if not isinstance(texto, str):
        raise TypeError("El texto debe ser una cadena.")
    if not isinstance(aad, bytes):
        raise TypeError("Los datos asociados deben ser bytes.")

    nonce = os.urandom(_LONGITUD_NONCE)
    return nonce + AESGCM(clave).encrypt(nonce, texto.encode("utf-8"), aad)


def descifrar(clave: bytes, blob: bytes, aad: bytes = b"") -> str:
    """Descifra un blob nonce+cifrado y valida su autenticidad con AES-GCM."""
    if not isinstance(clave, bytes) or len(clave) != _LONGITUD_CLAVE:
        raise ValueError("La clave debe tener exactamente 32 bytes.")
    if not isinstance(blob, bytes) or len(blob) < _LONGITUD_NONCE + _LONGITUD_TAG:
        raise ValueError("El blob debe contener un nonce y un cifrado autenticado.")
    if not isinstance(aad, bytes):
        raise TypeError("Los datos asociados deben ser bytes.")

    nonce, ciphertext = blob[:_LONGITUD_NONCE], blob[_LONGITUD_NONCE:]
    return AESGCM(clave).decrypt(nonce, ciphertext, aad).decode("utf-8")


def _paso_cadena(cadena: bytes) -> tuple[bytes, bytes]:
    """Obtiene una clave de mensaje y una siguiente clave de cadena."""
    material = HKDF(
        algorithm=SHA256(),
        length=2 * _LONGITUD_CLAVE,
        salt=None,
        info=b"taller-messenger/a1/chain-step/v1",
    ).derive(cadena)
    return material[:_LONGITUD_CLAVE], material[_LONGITUD_CLAVE:]


class SesionCadena:
    """Estado de emisor que conserva la cadena actual, no claves usadas."""

    def __init__(self, cadena: bytes) -> None:
        if not isinstance(cadena, bytes) or len(cadena) != _LONGITUD_CLAVE:
            raise ValueError("La clave de cadena debe tener exactamente 32 bytes.")
        self._cadena_actual = cadena

    @property
    def cadena_actual(self) -> bytes:
        """Devuelve el único estado de cadena que conserva esta sesión."""
        return self._cadena_actual

    def enviar(self, texto: str) -> bytes:
        """Cifra un mensaje y avanza la cadena sin guardar su clave de mensaje."""
        clave_mensaje, siguiente_cadena = _paso_cadena(self._cadena_actual)
        paquete = cifrar(clave_mensaje, texto)
        self._cadena_actual = siguiente_cadena
        return paquete
