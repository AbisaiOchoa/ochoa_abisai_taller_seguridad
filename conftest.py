from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

_PRUEBAS = {
    "A1-01": {
        "algoritmo": "A1",
        "propiedad": "determinismo",
        "descripcion": "Misma cadena e índice producen la misma clave",
        "esperado": "misma clave",
        "test": "test_A1_01",
    },
    "A1-02": {
        "algoritmo": "A1",
        "propiedad": "unicidad",
        "descripcion": "10 claves de mensaje distintas",
        "esperado": "10 claves distintas",
        "test": "test_A1_02",
    },
    "A1-03": {
        "algoritmo": "A1",
        "propiedad": "cifrado",
        "descripcion": "Cifrar y descifrar 10 mensajes",
        "esperado": "10/10 correctos",
        "test": "test_A1_03",
    },
    "A1-04": {
        "algoritmo": "A1",
        "propiedad": "borrado",
        "descripcion": "Clave usada y luego borrada no se recupera",
        "esperado": "no recuperable",
        "test": "test_A1_04",
    },
    "A2-01": {
        "algoritmo": "A2",
        "propiedad": "descifrado",
        "descripcion": "Descifrar los 6 mensajes",
        "esperado": "6/6 correctos",
        "test": "test_A2_01",
    },
    "A2-02": {
        "algoritmo": "A2",
        "propiedad": "integridad",
        "descripcion": "Un byte alterado del ciphertext",
        "esperado": "rechazado",
        "test": "test_A2_02",
    },
    "A2-03": {
        "algoritmo": "A2",
        "propiedad": "repetición",
        "descripcion": "Mensaje reenviado",
        "esperado": "rechazado",
        "test": "test_A2_03",
    },
    "A2-04": {
        "algoritmo": "A2",
        "propiedad": "forward secrecy",
        "descripcion": "Estado robado tras mensaje 3 no descifra mensaje 1",
        "esperado": "no descifrable",
        "test": "test_A2_04",
    },
    "A2-05": {
        "algoritmo": "A2",
        "propiedad": "post-compromise",
        "descripcion": "Estado robado antes del cambio de dirección no descifra tras él",
        "esperado": "no descifrable",
        "test": "test_A2_05",
    },
}
_POR_TEST = {prueba["test"]: id_prueba for id_prueba, prueba in _PRUEBAS.items()}
_CABECERA = [
    "id_prueba",
    "algoritmo",
    "propiedad",
    "descripcion",
    "esperado",
    "obtenido",
    "estado",
    "comentario",
]


@pytest.fixture
def registrar_resultado(request):
    def registrar(id_prueba: str, obtenido: str) -> None:
        request.node.user_properties.append(("id_prueba", id_prueba))
        request.node.user_properties.append(("obtenido", obtenido))

    return registrar


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if report.when != "call":
        return

    id_prueba = _POR_TEST.get(item.name)
    if id_prueba is None:
        return

    propiedades = dict(item.user_properties)
    obtenido = propiedades.get("obtenido", "prueba no completada")
    esperado = _PRUEBAS[id_prueba]["esperado"]
    estado = "OK" if report.passed and obtenido == esperado else "FALLA"

    if report.failed:
        detalle = getattr(getattr(report.longrepr, "reprcrash", None), "message", "")
        comentario = f"La prueba falló: {detalle or 'revisar el error de pytest'}"
    elif estado == "FALLA":
        comentario = f"El resultado obtenido ({obtenido}) no coincide con el esperado."
    else:
        comentario = "La verificación automatizada pasó."

    item.config._resultados_taller[id_prueba] = {
        "prueba": id_prueba,
        "esperado": esperado,
        "obtenido": obtenido,
        "estado": estado,
        "comentario": comentario,
    }


def pytest_configure(config):
    config._resultados_taller = {}


def pytest_sessionfinish(session, exitstatus):
    if session.testscollected != len(_PRUEBAS):
        return

    resultados = session.config._resultados_taller
    filas = []
    for id_prueba, definicion in _PRUEBAS.items():
        resultado = resultados.get(
            id_prueba,
            {
                "prueba": id_prueba,
                "esperado": definicion["esperado"],
                "obtenido": "prueba no ejecutada",
                "estado": "FALLA",
                "comentario": "La prueba no produjo un resultado.",
            },
        )
        filas.append(
            {
                "id_prueba": id_prueba,
                "algoritmo": definicion["algoritmo"],
                "propiedad": definicion["propiedad"],
                "descripcion": definicion["descripcion"],
                "esperado": resultado["esperado"],
                "obtenido": resultado["obtenido"],
                "estado": resultado["estado"],
                "comentario": resultado["comentario"],
            }
        )

    raiz = Path(__file__).resolve().parent
    with (raiz / "resultados.csv").open("w", newline="", encoding="utf-8") as archivo:
        escritor = csv.DictWriter(archivo, fieldnames=_CABECERA)
        escritor.writeheader()
        escritor.writerows(filas)

    registro_json = [
        {
            "prueba": fila["id_prueba"],
            "esperado": fila["esperado"],
            "obtenido": fila["obtenido"],
            "estado": fila["estado"],
        }
        for fila in filas
    ]
    with (raiz / "log_pruebas.json").open("w", encoding="utf-8") as archivo:
        json.dump(registro_json, archivo, ensure_ascii=False, indent=2)
        archivo.write("\n")
