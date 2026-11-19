# Informe corto

## Qué se implementó

- **A1:** derivación determinista de claves de 32 bytes con HKDF-SHA256 y cifrado autenticado AES-256-GCM. `SesionCadena` avanza su estado tras cada envío y no almacena claves de mensaje ya usadas.
- **A2:** simulación local de seis mensajes entre Alicia y Bob. Las cadenas avanzan por mensaje; los encabezados quedan autenticados como datos asociados; se rechazan mensajes repetidos o fuera de orden; y se usa X25519 para renovar el secreto de raíz.
- **Pruebas y resultados:** nueve pruebas pytest. Al ejecutar toda la suite, `conftest.py` actualiza `resultados.csv` y `log_pruebas.json` con los resultados de esa ejecución.

## Diferencias

- No es una implementación completa de Signal ni de su protocolo de establecimiento de sesión X3DH. El secreto inicial de la conversación se proporciona localmente.
- A2 procesa mensajes en orden estricto; no implementa mensajes fuera de orden, claves de mensajes pendientes, transporte, servidor ni persistencia.
- Para que A2-05 sea comprobable en un solo proceso sin intercambio de paquetes de negociación, `cambiar_direccion()` coordina la generación de un nuevo par X25519 en ambos extremos enlazados en memoria. En un protocolo real, cada extremo no accede al estado privado del otro: las claves públicas y las actualizaciones DH deben intercambiarse mediante mensajes autenticados. Esta coordinación es una abstracción de la simulación, no el flujo exacto de Signal.

## Limitaciones

- El ejemplo es educativo y no debe usarse para proteger comunicaciones reales. No gestiona autenticación inicial de identidades, verificación de claves, almacenamiento seguro, recuperación ante compromiso de forma completa ni metadatos.
- El borrado en Python significa que el estado de la sesión deja de conservar la clave usada; no garantiza sobrescribir todas las copias de memoria del proceso.
- E2EE no protege un dispositivo comprometido. El forward secrecy y la recuperación tras compromiso dependen de las claves que se hayan filtrado y del intercambio DH que realmente ocurra.
