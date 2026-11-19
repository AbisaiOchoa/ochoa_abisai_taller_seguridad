# Cifrado extremo a extremo y secreto hacia adelante

## Definición

1. El cifrado extremo a extremo (E2EE) protege el contenido de los mensajes para que solo los dispositivos de quienes participan puedan leerlo; el servidor y quien observe el tráfico reciben texto cifrado. No oculta necesariamente metadatos como quién se comunica, cuándo ni cuánto envía. Tampoco protege un dispositivo comprometido ni verifica por sí solo que la clave de identidad pertenezca a la persona esperada.

## Amenaza

2. El secreto hacia adelante (*forward secrecy*) limita el daño de una filtración posterior: obtener una clave actual no debería permitir descifrar mensajes protegidos por claves de mensaje anteriores que ya se eliminaron. Mitiga, por ejemplo, el robo posterior de las claves de un dispositivo o de una clave de cadena vigente; no revierte una intrusión que ocurrió cuando se enviaron los mensajes.

## Mecanismo

3. En el Double Ratchet de Signal, una cadena simétrica avanza con una función de derivación: de cada clave de cadena se obtiene una clave de mensaje y la siguiente clave de cadena. La clave de mensaje se elimina después de utilizarla, de modo que el estado posterior no conserva la clave anterior. Cuando cambia la clave DH, el secreto compartido nuevo se mezcla en la clave raíz y se deriva una cadena nueva. La actualización DH puede aportar recuperación tras un compromiso, bajo las condiciones del protocolo y cuando la clave nueva no era conocida por quien obtuvo el estado anterior.

## Fuentes

- Cohn-Gordon, K., Cremers, C., Dowling, B., Garratt, L. y Stebila, D. (2017). [A Formal Security Analysis of the Signal Messaging Protocol](https://eprint.iacr.org/2016/1013). IEEE EuroS&P.
- Marlinspike, M. y Perrin, T. [The Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/). Especificación de Signal.
