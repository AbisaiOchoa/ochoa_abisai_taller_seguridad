"""Simulación local y reducida de un Double Ratchet para seis mensajes."""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from a1_cadena import _paso_cadena, cifrar, descifrar

_LONGITUD_CLAVE = 32
_MAX_NUMERO_MENSAJE = 2**32 - 1


def _hkdf(material: bytes, longitud: int, etiqueta: bytes, salt: bytes | None = None) -> bytes:
    return HKDF(
        algorithm=SHA256(),
        length=longitud,
        salt=salt,
        info=b"taller-messenger/a2/" + etiqueta,
    ).derive(material)


def _publica_bytes(clave: X25519PublicKey) -> bytes:
    return clave.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _privada_bytes(clave: X25519PrivateKey) -> bytes:
    return clave.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _datos_asociados(numero: int, clave_publica: bytes) -> bytes:
    return b"taller-messenger/a2/header/v1" + struct.pack("!I", numero) + clave_publica


@dataclass(frozen=True)
class Paquete:
    """Encabezado autenticado y blob cifrado de un mensaje."""

    numero: int
    clave_publica: bytes
    cifrado: bytes


class Ratchet:
    """Ratchet reducido que procesa mensajes en orden y sin red."""

    def __init__(
        self,
        *,
        nombre: str,
        raiz: bytes,
        cadena_envio: bytes,
        cadena_recibido: bytes,
        clave_privada: X25519PrivateKey,
        clave_publica_remota: bytes,
    ) -> None:
        self.nombre = nombre
        self._raiz = raiz
        self._cadena_envio = cadena_envio
        self._cadena_recibido = cadena_recibido
        self._clave_privada = clave_privada
        self._clave_publica_remota = clave_publica_remota
        self._numero_envio = 0
        self._numero_recibido = 0
        self._par: Ratchet | None = None

    @property
    def clave_publica(self) -> bytes:
        return _publica_bytes(self._clave_privada.public_key())

    def enviar(self, texto: str) -> Paquete:
        """Cifra el siguiente mensaje y avanza solo la cadena de envío."""
        if self._numero_envio > _MAX_NUMERO_MENSAJE:
            raise OverflowError("Se agotó el espacio del número de mensaje.")

        numero = self._numero_envio
        clave_publica = self.clave_publica
        clave_mensaje, siguiente_cadena = _paso_cadena(self._cadena_envio)
        aad = _datos_asociados(numero, clave_publica)
        paquete = Paquete(
            numero=numero,
            clave_publica=clave_publica,
            cifrado=cifrar(clave_mensaje, texto, aad),
        )
        self._cadena_envio = siguiente_cadena
        self._numero_envio += 1
        return paquete

    def recibir(self, paquete: Paquete) -> str:
        """Valida el encabezado, descifra en orden y avanza el estado receptor."""
        if not isinstance(paquete, Paquete):
            raise TypeError("El paquete debe ser una instancia de Paquete.")
        if isinstance(paquete.numero, bool) or not isinstance(paquete.numero, int):
            raise ValueError("El número de mensaje debe ser un entero.")
        if not 0 <= paquete.numero <= _MAX_NUMERO_MENSAJE:
            raise ValueError("Número de mensaje fuera de rango.")
        if not isinstance(paquete.clave_publica, bytes) or len(paquete.clave_publica) != 32:
            raise ValueError("La clave pública X25519 debe tener 32 bytes.")

        cambio_dh = paquete.clave_publica != self._clave_publica_remota
        if cambio_dh:
            if paquete.numero != 0:
                raise ValueError("El primer mensaje de una cadena DH nueva debe ser el número 0.")
            publica_remota = X25519PublicKey.from_public_bytes(paquete.clave_publica)
            secreto_dh = self._clave_privada.exchange(publica_remota)
            material = _hkdf(secreto_dh, 64, b"root-step/v1", salt=self._raiz)
            raiz_candidata, cadena_candidata = material[:32], material[32:]
            numero_esperado = 0
        else:
            if paquete.numero < self._numero_recibido:
                raise ValueError("Mensaje repetido: el número ya fue recibido.")
            if paquete.numero > self._numero_recibido:
                raise ValueError("Mensaje fuera de secuencia.")
            raiz_candidata = self._raiz
            cadena_candidata = self._cadena_recibido
            numero_esperado = self._numero_recibido

        if paquete.numero != numero_esperado:
            raise ValueError("Número de mensaje inesperado.")

        clave_mensaje, siguiente_cadena = _paso_cadena(cadena_candidata)
        aad = _datos_asociados(paquete.numero, paquete.clave_publica)
        texto = descifrar(clave_mensaje, paquete.cifrado, aad)

        self._raiz = raiz_candidata
        self._cadena_recibido = siguiente_cadena
        self._clave_publica_remota = paquete.clave_publica
        self._numero_recibido = paquete.numero + 1
        return texto

    def cambiar_direccion(self) -> None:
        """Coordina una rotación X25519 y comienza una cadena de envío nueva.

        En esta simulación sin red, el par en memoria prepara también una clave
        efímera nueva. Un protocolo real necesita intercambiar esos encabezados
        mediante mensajes autenticados; no accede al estado del otro extremo.
        """
        if self._par is None:
            raise RuntimeError("La rotación coordinada requiere crear_conversacion().")

        clave_privada_nueva = X25519PrivateKey.generate()
        clave_privada_par_nueva = X25519PrivateKey.generate()
        publica_par_nueva = clave_privada_par_nueva.public_key()
        secreto_dh = clave_privada_nueva.exchange(publica_par_nueva)
        material = _hkdf(secreto_dh, 64, b"root-step/v1", salt=self._raiz)

        self._clave_privada = clave_privada_nueva
        self._clave_publica_remota = _publica_bytes(publica_par_nueva)
        self._raiz = material[:32]
        self._cadena_envio = material[32:]
        self._numero_envio = 0

        par = self._par
        par._clave_privada = clave_privada_par_nueva

    def copiar_estado(self) -> Ratchet:
        """Crea una copia independiente del estado actual para simular una filtración."""
        copia = Ratchet(
            nombre=self.nombre,
            raiz=self._raiz,
            cadena_envio=self._cadena_envio,
            cadena_recibido=self._cadena_recibido,
            clave_privada=X25519PrivateKey.from_private_bytes(
                _privada_bytes(self._clave_privada)
            ),
            clave_publica_remota=self._clave_publica_remota,
        )
        copia._numero_envio = self._numero_envio
        copia._numero_recibido = self._numero_recibido
        return copia


def crear_conversacion(secreto_inicial: bytes | None = None) -> tuple[Ratchet, Ratchet]:
    """Crea participantes Alicia y Bob con secreto y pares X25519 compartidos."""
    secreto = secreto_inicial if secreto_inicial is not None else os.urandom(_LONGITUD_CLAVE)
    if not isinstance(secreto, bytes) or len(secreto) < _LONGITUD_CLAVE:
        raise ValueError("El secreto inicial debe contener al menos 32 bytes.")

    raiz = _hkdf(secreto, _LONGITUD_CLAVE, b"initial-root/v1")
    cadena_a_b = _hkdf(raiz, _LONGITUD_CLAVE, b"chain/alicia-to-bob/v1")
    cadena_b_a = _hkdf(raiz, _LONGITUD_CLAVE, b"chain/bob-to-alicia/v1")
    privada_alicia = X25519PrivateKey.generate()
    privada_bob = X25519PrivateKey.generate()
    publica_alicia = _publica_bytes(privada_alicia.public_key())
    publica_bob = _publica_bytes(privada_bob.public_key())

    alicia = Ratchet(
        nombre="Alicia",
        raiz=raiz,
        cadena_envio=cadena_a_b,
        cadena_recibido=cadena_b_a,
        clave_privada=privada_alicia,
        clave_publica_remota=publica_bob,
    )
    bob = Ratchet(
        nombre="Bob",
        raiz=raiz,
        cadena_envio=cadena_b_a,
        cadena_recibido=cadena_a_b,
        clave_privada=privada_bob,
        clave_publica_remota=publica_alicia,
    )
    alicia._par = bob
    bob._par = alicia
    return alicia, bob
