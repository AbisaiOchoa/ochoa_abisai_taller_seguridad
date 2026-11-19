from __future__ import annotations

from cryptography.exceptions import InvalidTag
from dataclasses import replace

from a1_cadena import _paso_cadena, descifrar
from a2_ratchet import _datos_asociados, crear_conversacion


def test_A2_01(registrar_resultado):
    alicia, bob = crear_conversacion()
    originales = [f"mensaje {numero}" for numero in range(1, 4)]
    recibidos = [bob.recibir(alicia.enviar(texto)) for texto in originales]

    bob.cambiar_direccion()
    originales.extend(f"mensaje {numero}" for numero in range(4, 7))
    recibidos.extend(alicia.recibir(bob.enviar(texto)) for texto in originales[3:])

    correctos = sum(
        obtenido == esperado for obtenido, esperado in zip(recibidos, originales)
    )
    obtenido = f"{correctos}/6 correctos"
    registrar_resultado("A2-01", obtenido)
    assert recibidos == originales


def test_A2_02(registrar_resultado):
    alicia, bob = crear_conversacion()
    paquete = alicia.enviar("mensaje autenticado")
    cifrado_alterado = bytearray(paquete.cifrado)
    cifrado_alterado[-1] ^= 1
    adulterado = replace(paquete, cifrado=bytes(cifrado_alterado))
    rechazado = False
    try:
        bob.recibir(adulterado)
    except InvalidTag:
        rechazado = True

    obtenido = "rechazado" if rechazado else "aceptado"
    registrar_resultado("A2-02", obtenido)
    assert rechazado


def test_A2_03(registrar_resultado):
    alicia, bob = crear_conversacion()
    paquete = alicia.enviar("mensaje de un solo uso")
    bob.recibir(paquete)
    rechazado = False
    try:
        bob.recibir(paquete)
    except ValueError as error:
        rechazado = "repetido" in str(error).lower()

    obtenido = "rechazado" if rechazado else "aceptado"
    registrar_resultado("A2-03", obtenido)
    assert rechazado


def test_A2_04(registrar_resultado):
    alicia, bob = crear_conversacion()
    primer_paquete = None
    for numero in range(3):
        paquete = alicia.enviar(f"mensaje {numero + 1}")
        if numero == 0:
            primer_paquete = paquete
        bob.recibir(paquete)

    estado_filtrado = bob.copiar_estado()
    clave_del_siguiente_mensaje, _ = _paso_cadena(estado_filtrado._cadena_recibido)
    no_descifrable = False
    try:
        descifrar(
            clave_del_siguiente_mensaje,
            primer_paquete.cifrado,
            _datos_asociados(
                primer_paquete.numero,
                primer_paquete.clave_publica,
            ),
        )
    except InvalidTag:
        no_descifrable = True

    obtenido = "no descifrable" if no_descifrable else "descifrable"
    registrar_resultado("A2-04", obtenido)
    assert no_descifrable


def test_A2_05(registrar_resultado):
    alicia, bob = crear_conversacion()
    estado_filtrado = alicia.copiar_estado()
    bob.cambiar_direccion()
    paquete_nuevo = bob.enviar("mensaje posterior a la rotación")

    recibido = alicia.recibir(paquete_nuevo)
    no_descifrable = False
    try:
        estado_filtrado.recibir(paquete_nuevo)
    except InvalidTag:
        no_descifrable = True

    obtenido = "no descifrable" if no_descifrable and recibido else "descifrable"
    registrar_resultado("A2-05", obtenido)
    assert recibido == "mensaje posterior a la rotación"
    assert no_descifrable
