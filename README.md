# Generador de Reporte de Riesgos de Identity Protection desde CrowdStrike

Pipeline en Python para consultar CrowdStrike Identity Protection mediante GraphQL y FalconPy, descubrir riesgos asociados a un dominio, interpretar hallazgos por tipo de riesgo y generar un reporte final en Excel para análisis técnico, priorización y seguimiento operativo.

El proyecto está diseñado para equipos SOC, MSSP y analistas de identidad que necesitan convertir hallazgos de CrowdStrike Identity Protection en una salida accionable, reutilizable y trazable.

**Desarrollado por:** Bryan Varela Vargas

**Alias:** W4rded

**Rol:** Cybersecurity Analyst

---

## Tabla de contenido

- [Propósito](#propósito)
- [Qué hace el proyecto](#qué-hace-el-proyecto)
- [Requisitos](#requisitos)
- [Instalación rápida](#instalación-rápida)
- [Configuración](#configuración)
- [Permisos de API en CrowdStrike](#permisos-de-api-en-crowdstrike)
- [Uso](#uso)
- [Salida esperada](#salida-esperada)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Arquitectura interna](#arquitectura-interna)
- [Organización de salidas](#organización-de-salidas)
- [Modos de retención de artefactos](#modos-de-retención-de-artefactos)
- [Hojas del Excel](#hojas-del-excel)
- [Validación posterior a la ejecución](#validación-posterior-a-la-ejecución)
- [Troubleshooting](#troubleshooting)
- [Documentación adicional](#documentación-adicional)
- [Limitaciones conocidas](#limitaciones-conocidas)
- [Consideraciones de seguridad](#consideraciones-de-seguridad)
- [Mejoras futuras](#mejoras-futuras)
- [Referencias](#referencias)

---

## Propósito

El objetivo del proyecto es automatizar el proceso de consulta, conteo, parseo, correlación y presentación de riesgos de identidad detectados por CrowdStrike Identity Protection.

La salida principal es un workbook de Excel orientado a revisión técnica y priorización operativa. El pipeline también puede generar artefactos intermedios en JSON y CSV para auditoría, depuración de parsers y análisis de estructuras no soportadas.

En términos prácticos, el proyecto toma datos de Identity Protection, los organiza, los contextualiza y los transforma en un reporte reutilizable para equipos de tecnología, identidad y seguridad.

---

## Qué hace el proyecto

El pipeline automatiza las siguientes tareas:

- Descubre todos los `riskFactors.type` presentes en un dominio.
- Cuenta y clasifica riesgos por tipo.
- Aplica parsers específicos según el tipo de riesgo.
- Interpreta rutas de ataque y riesgos técnicos cuando el payload lo permite.
- Correlaciona hallazgos por entidad.
- Registra auditoría de errores, estructuras inesperadas y tipos de riesgo no soportados.
- Genera artefactos técnicos en JSON y CSV.
- Genera un Excel final orientado a análisis, priorización y seguimiento.

---

## Requisitos

### Requisitos generales

- Python 3.10 o superior.
- Acceso a CrowdStrike Falcon.
- Identity Protection habilitado en el tenant.
- API Client con permisos de Identity Protection.
- PowerShell en Windows.

### Requisitos para desarrollo

- Git.
- Editor de código, por ejemplo Visual Studio Code.
- Conocimiento básico de Python, GraphQL y estructuras JSON.

### Dependencias de Python

Las dependencias principales son:

```text
crowdstrike-falconpy
openpyxl
```

Deben estar declaradas en `requirements.txt`.

---

## Instalación rápida

Usa este flujo si vas a clonar el repositorio y ejecutar el proyecto desde cero.

```powershell
git clone <URL_DEL_REPOSITORIO>
cd Identity_Report

python -m venv .venv
.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
pip install -r requirements.txt
```

Verifica que las dependencias principales se hayan instalado correctamente:

```powershell
python -c "import falconpy; print(falconpy.__version__)"
python -c "import openpyxl; print(openpyxl.__version__)"
```

Si ambos comandos imprimen una versión, el ambiente está listo.

---

## Configuración

El proyecto usa variables de entorno. No se recomienda hardcodear credenciales, dominios ni datos de cliente dentro del código.

### Variables obligatorias

| Variable | Descripción |
| --- | --- |
| `FALCON_CLIENT_ID` | Client ID del API Client de CrowdStrike. |
| `FALCON_CLIENT_SECRET` | Client Secret del API Client de CrowdStrike. |
| `FALCON_TARGET_DOMAIN` | Dominio objetivo que será consultado en Identity Protection. |

### Variables recomendadas

| Variable | Descripción |
| --- | --- |
| `FALCON_DELIVERABLE_NAME` | Nombre comercial o corto del cliente para construir el nombre del Excel final. |
| `FALCON_BASE_URL` | URL base regional de API de CrowdStrike. |
| `FALCON_ARTIFACT_MODE` | Define si se conservan o eliminan artefactos intermedios. |

### Variables opcionales

| Variable | Valor sugerido | Descripción |
| --- | --- | --- |
| `FALCON_PAGE_SIZE` | `1000` | Tamaño de página para consultas paginadas. |
| `FALCON_OUTPUT_DIR` | `output` | Carpeta base para artefactos intermedios. |
| `FALCON_REPORT_NAME` | `identity_risk_report` | Nombre lógico de la corrida. |
| `FALCON_SAMPLE_LIMIT_PER_RISK` | `3` | Cantidad máxima de muestras raw por tipo de riesgo. |

### Ejemplo de configuración en PowerShell

```powershell
$env:FALCON_CLIENT_ID="TU_CLIENT_ID"
$env:FALCON_CLIENT_SECRET="TU_CLIENT_SECRET"
$env:FALCON_TARGET_DOMAIN="cliente.local"
$env:FALCON_DELIVERABLE_NAME="ACME"
$env:FALCON_PAGE_SIZE="1000"
$env:FALCON_OUTPUT_DIR="output"
$env:FALCON_REPORT_NAME="identity_risk_report"
$env:FALCON_SAMPLE_LIMIT_PER_RISK="3"
$env:FALCON_BASE_URL="https://api.us-2.crowdstrike.com"
$env:FALCON_ARTIFACT_MODE="final_only"
```

### Archivo `.env.example`

El repositorio incluye un archivo `.env.example` como plantilla de referencia.

Importante:

- El proyecto no carga automáticamente archivos `.env`.
- Las variables deben exportarse en la sesión de PowerShell antes de ejecutar.
- No se deben usar valores genéricos como `Cliente`, `Test` o `Demo` en una corrida real.
- No se deben guardar credenciales reales dentro del repositorio.

### Recomendación para `FALCON_BASE_URL`

Usa la URL regional de API, no la URL de consola.

Ejemplos válidos:

```text
https://api.crowdstrike.com
https://api.us-2.crowdstrike.com
```

El proyecto usa esta base para construir enlaces hacia la consola Falcon en el Excel final.

Ejemplo:

```text
https://api.crowdstrike.com      -> https://falcon.crowdstrike.com
https://api.us-2.crowdstrike.com -> https://falcon.us-2.crowdstrike.com
```

### Recomendación para `FALCON_DELIVERABLE_NAME`

`FALCON_DELIVERABLE_NAME` controla el nombre oficial del Excel final.

Buenas prácticas:

- Usar el nombre corto del cliente o del entregable.
- Revisarlo en cada corrida, igual que `FALCON_TARGET_DOMAIN`.
- Evitar valores genéricos como `Cliente`, `Test`, `Demo` o `Final`.
- Evitar reutilizar el mismo nombre para clientes distintos.
- Evitar incluir timestamps manuales; el proyecto agrega la fecha automáticamente.

Ejemplos válidos:

```text
ACME
Cliente_XYZ
VADER_LOCAL
```

Si no se define `FALCON_DELIVERABLE_NAME`, el proyecto usa `FALCON_TARGET_DOMAIN` como fallback.

---

## Permisos de API en CrowdStrike

El API Client debe tener permisos de lectura sobre los módulos de Identity Protection requeridos por el proyecto.

Permisos recomendados:

| Permiso | Nivel |
| --- | --- |
| `Identity Protection Assessment` | `Read` |
| `Identity Protection Detections` | `Read` |
| `Identity Protection Enforcement` | `Read` |
| `Identity Protection Entities` | `Read` |
| `Identity Protection GraphQL` | `Write` |
| `Identity Protection Health` | `Read` |
| `Identity Protection on-premise enablement` | `Read` |
| `Identity Protection Policy Rules` | `Read` |
| `Identity Protection Timeline` | `Read` |

El permiso clave para las consultas GraphQL es:

```text
Identity Protection GraphQL = Write
```

Aunque el uso principal del proyecto es de lectura, el endpoint GraphQL de Identity Protection requiere el scope `identity-protection-graphql:write`.

---

## Uso

Una vez configuradas las variables de entorno, ejecuta:

```powershell
python main.py
```

También puedes ejecutar el script directamente con el intérprete del entorno virtual:

```powershell
.venv\Scripts\python.exe main.py
```

---

## Salida esperada

El entregable principal es un archivo Excel con un nombre similar a:

```text
Identity_Risk_Assessment_<deliverable_name>_<YYYY-MM-DD>.xlsx
```

Ejemplo:

```text
Identity_Risk_Assessment_ACME_2026-04-20.xlsx
```

Si ya existe un archivo con el mismo nombre para la misma fecha, el proyecto crea una versión incremental para evitar sobreescritura:

```text
Identity_Risk_Assessment_ACME_2026-04-20_v2.xlsx
Identity_Risk_Assessment_ACME_2026-04-20_v3.xlsx
```

---

## Estructura del proyecto

```text
Identity_Report/
|-- main.py
|-- config.py
|-- queries.py
|-- discovery.py
|-- parser_registry.py
|-- risk_catalog.py
|-- parsers.py
|-- audit.py
|-- analytics.py
|-- actionability.py
|-- reporting.py
|-- utils.py
|-- requirements.txt
|-- .env.example
|-- README.md
|-- docs/
|   |-- README.md
|   |-- l1-knowledge-base.md
|   |-- identity-references.md
|   |-- mssp-operations.md
|   `-- risk-domains.md
`-- output/
```

La carpeta `output/` no necesita existir en el repositorio. El proyecto la crea automáticamente en tiempo de ejecución.

---

## Arquitectura interna

El proyecto está organizado por responsabilidad para reducir acoplamiento entre consulta, parseo, auditoría y salida final.

| Archivo | Responsabilidad |
| --- | --- |
| `main.py` | Orquesta la ejecución general del pipeline. |
| `config.py` | Carga y valida configuración desde variables de entorno. |
| `queries.py` | Define consultas GraphQL de discovery y detalle. |
| `discovery.py` | Ejecuta consultas GraphQL con FalconPy y pagina resultados. |
| `risk_catalog.py` | Centraliza metadata de riesgos: título, dominio, impacto y remediación. |
| `parser_registry.py` | Decide qué parser usar para cada `risk_type`. |
| `parsers.py` | Transforma payloads de CrowdStrike en filas técnicas y, cuando el payload lo permite, genera filas de rutas de ataque. |
| `audit.py` | Registra tipos desconocidos, errores de parser, issues de estructura y muestras raw durante el proceso de parsing. |
| `analytics.py` | Construye correlaciones por entidad y agregados ejecutivos usados durante la generación del reporte. |
| `actionability.py` | Calcula prioridad, accionabilidad y siguiente paso sugerido durante la preparación de salidas. |
| `reporting.py` | Genera CSV, JSON, Excel final y aplica retención de artefactos. |
| `utils.py` | Contiene helpers de IO, enlaces Falcon y salida de consola. |

Orden lógico de ejecución:

```text
main.py
  -> config.py
  -> discovery.py
  -> parsers.py
       -> audit.py
  -> reporting.py
       -> analytics.py
       -> actionability.py
       -> generación de CSV/JSON/Excel
       -> retención o limpieza de artefactos
```

Nota:

`audit.py` se utiliza durante el parsing para registrar errores, estructuras inesperadas y riesgos no soportados. `analytics.py` y `actionability.py` se ejecutan durante la generación de salidas, no como una fase independiente previa a `reporting.py`.

---

## Organización de salidas

El proyecto separa las salidas en dos niveles.

### 1. Artefactos de trabajo

Se guardan dentro de:

```text
<FALCON_OUTPUT_DIR>/runs/<report_name>_<timestamp>/
```

Por defecto, si `FALCON_OUTPUT_DIR` no se modifica, la ruta será:

```text
output/runs/<report_name>_<timestamp>/
```

Dependiendo del modo de artefactos, pueden generarse archivos como:

```text
*_discovery_raw.json
*_detail_raw.json
*_risk_inventory.csv
*_parser_inventory.csv
*_parsed_risks.csv
*_attack_paths.csv
*_unknown_risk_types.csv
*_parser_errors.csv
*_structure_issues.csv
*_raw_samples_overview.csv
*_raw_samples.json
```

Estos archivos sirven para trazabilidad técnica, auditoría, debugging y evolución de parsers.

### 2. Reporte final

El Excel final se genera en el directorio padre de `FALCON_OUTPUT_DIR`.

Con la configuración por defecto:

```powershell
$env:FALCON_OUTPUT_DIR="output"
```

el Excel se genera en la raíz del proyecto, ya que el directorio padre de `output/` corresponde a la carpeta base del repositorio.

Si `FALCON_OUTPUT_DIR` se cambia a otra ruta, el Excel final se generará en el padre de esa ruta. Por ejemplo:

```powershell
$env:FALCON_OUTPUT_DIR="C:\Temp\identity_output"
```

En ese caso, el Excel final quedaría en:

```text
C:\Temp\
```

Esto permite separar artefactos intermedios del entregable final, pero debe tomarse en cuenta si se personaliza `FALCON_OUTPUT_DIR`.

---

## Modos de retención de artefactos

El comportamiento se controla con:

```text
FALCON_ARTIFACT_MODE
```

Valores soportados:

```text
final_only
standard
debug
```

### `final_only`

Modo recomendado para operación MSSP.

Comportamiento esperado:

- Genera el Excel final.
- Intenta eliminar la carpeta de artefactos intermedios de la corrida.
- No conserva JSON ni CSV técnicos cuando la limpieza se completa correctamente.

Uso recomendado:

- Ejecución normal para entrega de reporte a cliente.
- Ambientes donde no se desea persistir evidencia sensible del tenant.

Nota técnica:

La eliminación de artefactos se realiza como una operación de limpieza posterior a la generación del reporte. Si Windows, OneDrive, un antivirus, un proceso externo o permisos del sistema bloquean archivos o carpetas, la carpeta de artefactos puede conservarse y el proyecto mostrará una nota en consola. En ese caso, se debe revisar y eliminar manualmente la carpeta de la corrida si contiene información sensible.

### `standard`

Modo intermedio.

Comportamiento:

- Conserva la carpeta `<FALCON_OUTPUT_DIR>/runs/<corrida>/`.
- Elimina artefactos raw sensibles.
- Conserva CSV técnicos útiles para revisión operativa.

Archivos purgados en este modo:

```text
*_discovery_raw.json
*_detail_raw.json
*_raw_samples.json
```

Uso recomendado:

- Revisión técnica interna.
- Validación de resultados sin retener payload raw completo.

### `debug`

Modo de desarrollo.

Comportamiento:

- Conserva todos los artefactos de la corrida.
- Mantiene material útil para depurar parsers o validar cambios estructurales.

Uso recomendado:

- Investigación de errores.
- Incorporación de nuevos parsers.
- Validación de cambios en el esquema de respuesta.

Para operación normal en MSSP:

```powershell
$env:FALCON_ARTIFACT_MODE="final_only"
```

Usa `debug` solo cuando realmente necesites investigar un fallo o construir soporte para nuevos tipos de riesgo.

---

## Hojas del Excel

El workbook final está optimizado para operación MSSP y revisión técnica con cliente.

Dependiendo de la corrida y de los datos encontrados, puede incluir:

| Hoja | Descripción |
| --- | --- |
| `Resumen Ejecutivo` | KPIs, focos principales, acciones sugeridas y lectura rápida. |
| `Plan de Atencion` | Vista principal para analistas con prioridad, accionabilidad, evidencia y enlace Falcon. |
| `Riesgos Prioritarios` | Riesgos agregados por volumen, dominio de atención, criticidad y concentración. |
| `Entidades Criticas` | Entidades con múltiples riesgos correlacionados. |
| `Rutas de Ataque` | Rutas observadas cuando CrowdStrike devuelve datos suficientes. |
| `Resumen por Riesgo` | Inventario agregado por `risk_type`, título, dominio, cantidad y porcentaje. |
| `Detalle Operativo` | Detalle técnico para revisión y remediación. |

Notas importantes:

- El Excel final no muestra hojas de auditoría interna ni columnas raw de parser.
- Las hojas de auditoría se conservan como CSV/JSON solo cuando `FALCON_ARTIFACT_MODE` lo permite.
- La hoja oculta `_chart_data` puede existir como soporte interno para gráficos y no debe usarse como vista de análisis.

---

## Validación posterior a la ejecución

Después de correr el pipeline, valida lo siguiente:

1. Que el Excel final se haya generado en la ubicación esperada según `FALCON_OUTPUT_DIR`.
2. Que el nombre del archivo corresponda al cliente correcto.
3. Que `FALCON_TARGET_DOMAIN` apunte al dominio esperado.
4. Que `FALCON_DELIVERABLE_NAME` corresponda al cliente o entregable correcto.
5. Que la consola no muestre errores críticos de parser o estructura.
6. Que no existan tipos de riesgo `Unclassified` sin revisión.
7. Que los enlaces Falcon del Excel apunten a la región correcta.
8. Que las hojas principales tengan datos coherentes antes de compartir el reporte.

Orden sugerido de revisión:

1. `Resumen Ejecutivo`
2. `Plan de Atencion`
3. `Riesgos Prioritarios`
4. `Entidades Criticas`
5. `Rutas de Ataque`, si existe
6. `Detalle Operativo`

No se recomienda entregar el reporte a cliente si existen errores de parser, estructuras inesperadas o riesgos no clasificados sin revisión técnica previa.

---

## Troubleshooting

### PowerShell bloquea la activación del entorno virtual

Error típico:

```text
running scripts is disabled on this system
```

Solución temporal para la sesión actual:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.venv\Scripts\Activate.ps1
```

### `python` no responde o no se reconoce

Valida la instalación:

```powershell
python --version
```

Si no responde, instala Python desde el sitio oficial y marca la opción `Add Python to PATH`.

### Falta `falconpy`

Instala dependencias:

```powershell
pip install -r requirements.txt
```

Valida la instalación:

```powershell
python -c "import falconpy; print(falconpy.__version__)"
```

### Falta `openpyxl`

Instala dependencias:

```powershell
pip install -r requirements.txt
```

O instala el paquete directamente:

```powershell
pip install openpyxl
```

### No se genera el Excel

Valida:

1. Que `openpyxl` esté instalado.
2. Que las variables obligatorias estén configuradas.
3. Que el API Client tenga permisos correctos.
4. Que no existan errores de autenticación, permisos, GraphQL o escritura del archivo final.
5. Que la ruta donde se va a guardar el Excel permita escritura.

El workbook puede construirse aunque algunas listas vengan vacías, por lo que la ausencia de datos no necesariamente impide la generación del Excel.

### Error HTTP 403 `scope not permitted`

Valida que el API Client tenga el permiso:

```text
Identity Protection GraphQL = Write
```

Este permiso es requerido para el endpoint GraphQL de Identity Protection.

### Error de autenticación

Valida:

- `FALCON_CLIENT_ID`
- `FALCON_CLIENT_SECRET`
- región configurada en `FALCON_BASE_URL`
- permisos del API Client
- que el tenant tenga Identity Protection habilitado

### Enlaces Falcon incorrectos en el Excel

Verifica que `FALCON_BASE_URL` sea una URL regional de API válida.

Ejemplos:

```text
https://api.crowdstrike.com
https://api.us-2.crowdstrike.com
```

No uses la URL de consola como valor de `FALCON_BASE_URL`.

### Aparecen riesgos `Unclassified`

Significa que el proyecto recibió un `risk_type` que aún no está catalogado localmente.

Acción recomendada:

1. Revisar el payload raw si el modo de artefactos lo permite.
2. Validar el hallazgo directamente en Falcon.
3. Confirmar significado operativo del riesgo.
4. Agregar metadata en `risk_catalog.py`.
5. Crear o ajustar parser si el payload contiene estructura útil.

### Aparecen `Parser errors` o `Structure issues`

No se recomienda entregar el reporte como final sin revisión.

Acción recomendada:

1. Ejecutar temporalmente con `FALCON_ARTIFACT_MODE="debug"`.
2. Revisar archivos de auditoría.
3. Identificar el `risk_type` afectado.
4. Validar si CrowdStrike cambió estructura, `__typename` o campos del payload.
5. Ajustar parser o catálogo según corresponda.

---

## Documentación adicional

La documentación extendida del proyecto se encuentra en la carpeta [`docs/`](docs/).

Material recomendado:

- [Base de conocimiento para revisión L1](docs/l1-knowledge-base.md)
- [Referencias técnicas de identidad](docs/identity-references.md)
- [Operación en entorno MSSP](docs/mssp-operations.md)
- [Dominios de atención y criterios de interpretación](docs/risk-domains.md)

Esta documentación está separada del README principal para que quienes solo necesitan ejecutar el proyecto encuentren rápidamente instalación, configuración y uso, mientras que analistas L1, L2 o responsables de identidad puedan consultar material operativo y técnico más profundo.

---

## Limitaciones conocidas

- El proyecto depende del esquema actual que devuelve CrowdStrike Identity Protection por GraphQL.
- No todos los riesgos devuelven el mismo nivel de detalle.
- Algunos riesgos pueden devolver únicamente `type`, `__typename` y severidad de entidad.
- La severidad mostrada corresponde a la entidad, no necesariamente a cada `riskFactor` individual.
- Si CrowdStrike cambia `__typename`, campos o estructura de `attackPath`, puede aumentar la cantidad de hallazgos en auditoría.
- El proyecto prioriza continuidad ante riesgos nuevos, parsers no soportados o estructuras inesperadas dentro de payloads válidos. En esos casos registra auditoría y continúa cuando es posible.
- Errores de autenticación, permisos, HTTP, GraphQL o fallos críticos de consulta pueden detener la ejecución, ya que impiden obtener datos válidos desde CrowdStrike.
- El reporte no reemplaza la validación en Falcon ni la investigación del equipo de identidad.
- Las recomendaciones generadas deben validarse con owner, criticidad, uso legítimo y ventana de cambio antes de remediar.

---

## Consideraciones de seguridad

- No incluir credenciales reales en el repositorio.
- No versionar archivos reales generados desde tenants de clientes.
- No subir contenido de `output/` si contiene evidencia sensible.
- Usar `FALCON_ARTIFACT_MODE="final_only"` para corridas operativas normales.
- Usar `debug` solo cuando sea necesario investigar errores o crear soporte para nuevos parsers.
- Validar cliente, dominio y región antes de cada ejecución.
- Evitar compartir artefactos raw fuera del equipo autorizado.

Recomendación de `.gitignore`:

```gitignore
.venv/
__pycache__/
*.pyc

.env
output/
*.xlsx

*_raw.json
*_detail_raw.json
*_discovery_raw.json
*_raw_samples.json
```

---

## Mejoras futuras

Posibles mejoras del proyecto:

- Carga automática opcional de `.env`.
- Tests unitarios para parsers y validaciones.
- Mayor cobertura de parsers especializados.
- Soporte para múltiples dominios en una misma ejecución.
- Ejecución por lote para entornos MSSP.
- Generación de PDF ejecutivo adicional.
- Exportación opcional a formatos compatibles con herramientas de ticketing.
- Validación previa de permisos antes de ejecutar consultas principales.
- Modo dry-run para validar configuración sin generar reporte.

---

## Referencias

- [FalconPy SDK para Python](https://github.com/CrowdStrike/falconpy)
- [Documentación de FalconPy](https://www.falconpy.io/)
- [Identity Protection en FalconPy](https://www.falconpy.io/Service-Collections/Identity-Protection.html)
- [CrowdStrike Developer Center](https://developer.crowdstrike.com/)
- [CrowdStrike OpenAPI Docs](https://developer.crowdstrike.com/docs/openapi/)
- [Python venv](https://docs.python.org/3/library/venv.html)
- [PowerShell Set-ExecutionPolicy](https://learn.microsoft.com/powershell/module/microsoft.powershell.security/set-executionpolicy)
