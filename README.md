# Taller: seguridad en mensajería

Requiere Python 3.11. Desde PowerShell, en la carpeta del proyecto:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest -q
```

La suite completa ejecuta nueve pruebas. Al terminar, genera o actualiza `resultados.csv` y `log_pruebas.json` en la raíz.

Para salir del entorno virtual:

```powershell
deactivate
```
