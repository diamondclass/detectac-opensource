src rebuilt by muse spark 1.3 xhigh
la src obtenida de: no sé jajasalu2
versión: no sé, octubre 3?
no es mia jajsalu2

--------------------

# DetectAC (open-source rebuild)

Scanner de cheat-traces para Windows. Un binario por juego (11 variantes).
Al terminar cada scan genera un **reporte HTML local** estilo dashboard
con subpáginas por nivel (Critical / Warning / Detection / Info) y la
lista completa de entries al final.

| `--game=` | exe resultante |
|---|---|
| `minecraft`, `siege`, `gmod`, `fivem`, `freefire`, `roblox`, `fortnite`, `cod`, `rust`, `dayz`, `cs` | `build\detect\detect-<juego>.exe` |

## Uso

1. Ejecutar como **administrador**.
2. Aceptar los ToS → el scan arranca solo, **sin PIN**.
3. Al terminar se guarda `detect-report-<juego>-<fecha-hora>.html` junto al
   exe y se abre automáticamente en el navegador.

![reporte](https://i.imgur.com/2oHSdkU.png)

## Build

Requisitos: [xmake](https://xmake.io) + Visual Studio Build Tools (MSVC).
Todo lo demás viene vendoreado en `ext/`.

```powershell
# Interactivo (menú de variantes)
.\build.ps1

# Directo
.\build.ps1 -Game minecraft
.\build.ps1 -Game minecraft -Mode debug
```

CI (`.github/workflows/build.yml`): buildea en `windows-latest` y sube el
exe como artifact. En push/PR va minecraft release; manual, cualquier
juego/modo.

## Notas

- El scan funciona **offline**: si el servidor no responde, igual completa
  y el reporte local se genera igual (el upload es best-effort).
- **Caché de reglas**: custom strings, reglas YARA y tema se descargan
  cuando hay server y se guardan en `detect-cache/` junto al exe; sin
  server se reutilizan. Para poblar la caché hace falta **una** corrida
  online con PIN válido (renombrar el exe a
  `detect-<juego>-<8 dígitos>.exe`); después sirve para todas las
  corridas offline.
- El PIN por nombre de archivo se ignora por completo.
- Si el auto-open del reporte molesta, sacar `open_local_report()` en
  `detect/detections/detection_root.cpp`.
- Cold build ~20-30 min; rebuilds incrementales, segundos.
- Conviene excluir la carpeta del repo del antivirus para compilar más rápido.
