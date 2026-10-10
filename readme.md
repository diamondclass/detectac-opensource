src rebuilt by muse spark 1.3 xhigh
la src obtenida de: no sé jajasalu2
versión: no sé, octubre 3?
no es mia jajsalu2

--------------------

# detect scanner

Scanner de cheat-traces para Windows. Un binario por juego (11 variantes),
compilado con [xmake](https://xmake.io) + MSVC. Todas las dependencias
vienen vendoreadas en `ext/`.

| `--game=` | exe resultante |
|---|---|
| `minecraft`, `siege`, `gmod`, `fivem`, `freefire`, `roblox`, `fortnite`, `cod`, `rust`, `dayz`, `cs` | `build\detect\detect-<juego>.exe` |

## Build

Ver `BUILD.md` (original del proyecto). Resumen:

```powershell
# Interactivo (menú, este es el flujo oficial)
.\build.ps1

# Directo, sin menú
.\build.ps1 -Game minecraft
.\build.ps1 -Game minecraft -Mode debug
.\build.ps1 -Clean
```

Equivalente manual con xmake (lo que hace `build.ps1` por dentro):

```powershell
xmake config -m release -p windows -a x64 --game=minecraft --builddir=build\intermediate\minecraft
xmake -j 4
# -> build\intermediate\minecraft\windows\x64\release\detect-minecraft.exe
```

## Cambios locales (vs upstream)

1. **Sin PIN**: el scan arranca solo al aceptar los ToS. Se eliminó la
   pantalla de PIN y el chequeo de sesión contra el servidor del camino
   crítico (`detect/UI/webview_ui.cpp`, `detect/detections/detection_root.cpp`).
2. **Reporte HTML local**: al terminar, los logs en memoria se vuelcan a
   `detect-report-<juego>-<fecha-hora>.html` junto al exe, y se abre solo
   en el navegador (`Logger::save_local_html_report()` en
   `detect/utils/logger/logger.h`, guardado **antes** del `flush_logs`
   porque ese vacía el buffer).
3. **Upload al servidor = best-effort**: si `detect.ac` no responde, el scan
   igual completa y el reporte local se genera igual.
4. **Shim `DWMWCP_DONOTROUND`**: el SDK instalado (10.0.19041) no trae esa
   constante (requiere SDK ≥ 22000); se agregó el `#define` guardado
   siguiendo el patrón ya existente en `detect/UI/webview_ui.cpp`.
5. **CI**: `.github/workflows/build.yml` buildea en `windows-latest`
   (push/PR: minecraft release; manual: cualquier juego/modo) y sube el
   exe como artifact.

## Cosas a tener en cuenta

- **Correr como administrador**: el exe exige admin sí o sí (lo chequea al
  arrancar y si no, muestra error y sale).
- **El PIN ahora se ignora**: el exe `detect-minecraft.exe` da PIN
  `00000000` por nombre de archivo; no importa, ya no se usa para nada.
- **El reporte se abre solo**: al terminar el scan se lanza el `.html` con
  el programa por defecto. Si molesta, sacar el `open_local_report()` en
  `detection_root.cpp`.
- **ToS sigue apareciendo**: solo se salteó el PIN, no los términos. El scan
  no arranca hasta aceptar.
- **Antivirus**: excluir la carpeta del repo del escaneo en tiempo real de
  Defender; si no, el build tarda muchísimo más (miles de `.obj`/`.pch`).
- **Tiempos en esta máquina (4 CPUs, compilador cruzado x86→x64)**:
  cold build ~25 min por variante; rebuild incremental, segundos.
- **Toolchain parcial**: solo existe `Hostx86\x64` (VS2019 14.29.30133), no
  `Hostx64` ni `vcvars64.bat`. Hay que cargar `vcvarsx86_amd64.bat` y pasar
  `--vs_toolset=14.29.30133` a mano; `build.ps1` tal cual **no** funciona acá
  porque busca `Hostx64`. En CI (runner con VS completo) sí anda directo.
- **`vswhere` roto**: no reporta instancias aunque BuildTools existe; xmake
  igual detecta MSVC si el entorno de `vcvars` ya está cargado en la sesión.
- **xmake no queda en PATH**: está en `C:\Program Files\xmake`; agregar a
  mano (`$env:Path = "C:\Program Files\xmake;$env:Path"`) o reabrir terminal.
- **CI gasta minutos**: cada variante son ~15 min en runner; el workflow por
  defecto solo buildea minecraft. No poner matriz de las 11 sin motivo.
- **`build.ps1 -Clean`**: borra `build/`, `.xmake/`; por juego con
  `-Clean -Game <nombre>`.
- **No commitear**: `build/`, `.xmake/`, `*.exe`, `*.pdb` ya están en
  `.gitignore`. Los `.lib` de `ext/lib/` SÍ van al repo (son dependencias).
