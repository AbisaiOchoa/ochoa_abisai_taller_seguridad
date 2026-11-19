from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag

from a1_cadena import SesionCadena, cifrar, descifrar, derivar_clave


def test_A1_01(registrar_resultado):
    cadena = b"cadena-demo-32-bytes-abcdefghij"
    primera = derivar_clave(cadena, 7)
    segunda = derivar_clave(cadena, 7)
    obtenido = "misma clave" if primera == segunda else "claves distintas"
    registrar_resultado("A1-01", obtenido)
    assert primera == segunda


def test_A1_02(registrar_resultado):
    cadena = b"cadena-demo-32-bytes-abcdefghij"
    claves = {derivar_clave(cadena, indice) for indice in range(10)}
    obtenido = f"{len(claves)} claves distintas"
    registrar_resultado("A1-02", obtenido)
    assert len(claves) == 10


def test_A1_03(registrar_resultado):
    cadena = b"cadena-demo-32-bytes-abcdefghij"
    textos = [f"mensaje de prueba {indice}" for indice in range(10)]
    descifrados = [
        descifrar(
            (clave := derivar_clave(cadena, indice)),
            cifrar(clave, texto),
        )
        for indice, texto in enumerate(textos)
    ]
    correctos = sum(obtenido == esperado for obtenido, esperado in zip(descifrados, textos))
    obtenido = f"{correctos}/10 correctos"
    registrar_resultado("A1-03", obtenido)
    assert descifrados == textos


def test_A1_04(registrar_resultado):
    sesion = SesionCadena(os.urandom(32))
    paquete = sesion.enviar("clave de mensaje efímera")
    clave_derivada_del_estado_actual = derivar_clave(sesion.cadena_actual, 0)
    no_recuperable = False
    try:
        descifrar(clave_derivada_del_estado_actual, paquete)
    except InvalidTag:
        no_recuperable = True

    obtenido = "no recuperable" if no_recuperable else "recuperable"
    registrar_resultado("A1-04", obtenido)
    assert no_recuperable
