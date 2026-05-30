# Generador de Reporte de Riesgos de Identity Protection desde CrowdStrike

Pipeline en Python para consultar CrowdStrike Identity Protection por GraphQL usando FalconPy, descubrir riesgos en un dominio, interpretarlos por tipo y generar un reporte tecnico final en Excel, junto con artefactos intermedios de analisis y auditoria.

**Desarrollado por:** Bryan Varela Vargas (Aka. W4rded)  
**Rol:** Cybersecurity Analyst

## Proposito del proyecto

Este proyecto existe para convertir hallazgos de CrowdStrike Identity Protection en un reporte tecnico y ejecutivo reutilizable para distintos clientes.

Su proposito principal es:

- automatizar discovery, conteo, parseo y correlacion de riesgos de identidad;
- presentar los resultados en un Excel listo para analistas y responsables tecnicos;
- dejar trazabilidad controlada para evolucionar parsers y auditar cambios futuros;
- reducir trabajo manual de exportacion, interpretacion y consolidacion de hallazgos.

En otras palabras: toma datos de Identity Protection, los organiza, los contextualiza y los transforma en una salida accionable para equipos de tecnologia y seguridad.

## Contenido

- [Proposito del proyecto](#proposito-del-proyecto)
- [Objetivo](#objetivo)
- [Estructura](#estructura)
- [Requisitos](#requisitos)
- [Setup en Windows](#setup-en-windows)
  - [Ruta 1. Solo ejecucion](#ruta-1-solo-ejecucion)
  - [Ruta 2. Desarrollo](#ruta-2-desarrollo)
- [Instalacion rapida](#instalacion-rapida)
- [Permisos de API en CrowdStrike](#permisos-de-api-en-crowdstrike)
- [Configuracion](#configuracion)
- [Uso](#uso)
- [Flujo funcional](#flujo-funcional)
- [Arquitectura interna](#arquitectura-interna)
- [Organizacion de salidas](#organizacion-de-salidas)
- [Retencion de artefactos sensibles](#retencion-de-artefactos-sensibles)
- [Nota sobre `output/`](#nota-sobre-output)
- [Hojas del Excel](#hojas-del-excel)
- [Dominios de atencion](#dominios-de-atencion)
- [Nota sobre severidad](#nota-sobre-severidad)
- [Revision recomendada despues de ejecutar](#revision-recomendada-despues-de-ejecutar)
- [Guia L1 de atencion](#guia-l1-de-atencion)
- [Cambio de cliente en entorno MSSP](#cambio-de-cliente-en-entorno-mssp)
- [Troubleshooting](#troubleshooting)
- [Referencias tecnicas para analistas](#referencias-tecnicas-para-analistas)
- [Nota para analistas](#nota-para-analistas)
- [Limitaciones conocidas](#limitaciones-conocidas)

## Objetivo

Este proyecto automatiza el flujo para:

- descubrir todos los `riskFactors.type` presentes en un dominio;
- contar y clasificar riesgos;
- aplicar parsers por tipo de riesgo;
- interpretar rutas de ataque y riesgos tecnicos;
- correlacionar hallazgos por entidad;
- registrar auditoria de errores, estructuras inesperadas y tipos sin soporte;
- generar JSON, CSV y un Excel tecnico final.

## Estructura

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
|-- reporting.py
|-- utils.py
|-- requirements.txt
|-- .env.example
|-- README.md
`-- output/
```

## Requisitos

### Comunes

- Python 3.10 o superior
- acceso a CrowdStrike Falcon con Identity Protection habilitado
- credenciales API con permisos de Identity Protection
- PowerShell en Windows

### Solo para desarrollo

- Git para clonar el repositorio y actualizar codigo

Dependencias:

```text
crowdstrike-falconpy
openpyxl
```

## Setup en Windows

Este proyecto puede prepararse de dos formas:

- `Solo ejecucion`: para analistas que solo necesitan correr el reporte
- `Desarrollo`: para quien va a modificar codigo, actualizar parsers o mantener el proyecto

<details>
<summary><strong>Ruta 1. Solo ejecucion</strong></summary>

Pensada para un analista que recibe la carpeta del proyecto ya descargada o comprimida y solo necesita ejecutarlo en Windows.

#### 1. Instalar prerrequisitos del sistema

Verifica que la maquina tenga:

- Python 3.10 o superior
- acceso a internet para instalar dependencias
- acceso al tenant de CrowdStrike correspondiente

Comandos de validacion:

```powershell
python --version
```

Si `python` no responde correctamente, instala Python desde `https://www.python.org/downloads/windows/` y marca la opcion `Add Python to PATH`.

#### 2. Copiar o extraer el proyecto

Si recibiste el proyecto como `.zip` o carpeta compartida, extraelo o copialo a una ruta local, por ejemplo:

```text
C:\Tools\Identity_Report
```

Luego entra a la carpeta:

```powershell
cd C:\Tools\Identity_Report
```

#### 3. Crear entorno virtual

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Si PowerShell bloquea la activacion por politica de ejecucion, puedes usar temporalmente:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.venv\Scripts\Activate.ps1
```

#### 4. Actualizar `pip` e instalar dependencias

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

#### 5. Verificar dependencias clave

```powershell
python -c "import falconpy; print(falconpy.__version__)"
python -c "import openpyxl; print(openpyxl.__version__)"
```

#### 6. Preparar variables de entorno

Define al menos:

- `FALCON_CLIENT_ID`
- `FALCON_CLIENT_SECRET`
- `FALCON_TARGET_DOMAIN`

Adicional recomendado para una entrega formal:

- `FALCON_DELIVERABLE_NAME`

Importante:

- revisa `FALCON_DELIVERABLE_NAME` en cada cliente igual que `FALCON_TARGET_DOMAIN`
- no uses placeholders genericos como `Cliente`, `Test` o `Demo` en una corrida real
- este valor define el nombre oficial del Excel que probablemente compartiras con el cliente

Ejemplo recomendado:

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

#### 7. Ejecutar el pipeline

```powershell
python main.py
```

O directamente, sin activar la `.venv`:

```powershell
.venv\Scripts\python.exe main.py
```

#### 8. Validar el resultado

Al finalizar, revisa:

1. el Excel final en la raiz del proyecto
2. la consola para confirmar si hubo `Parser errors`, `Structure issues` o `Requires review`
3. las hojas `Resumen Ejecutivo`, `Plan de Atencion`, `Riesgos Prioritarios`, `Entidades Criticas` y `Detalle Operativo`

</details>

<details>
<summary><strong>Ruta 2. Desarrollo</strong></summary>

Pensada para quien necesita clonar el repositorio, modificar el codigo, ajustar parsers y mantener el proyecto.

#### 1. Instalar prerrequisitos del sistema

Verifica que la maquina tenga:

- Python 3.10 o superior
- Git
- acceso a internet para instalar dependencias

Comandos de validacion:

```powershell
python --version
git --version
```

#### 2. Clonar el repositorio

```powershell
git clone <URL_DEL_REPOSITORIO>
cd Identity_Report
```

#### 3. Crear entorno virtual

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Si PowerShell bloquea la activacion por politica de ejecucion, puedes usar temporalmente:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.venv\Scripts\Activate.ps1
```

#### 4. Actualizar `pip` e instalar dependencias

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

#### 5. Verificar dependencias clave

```powershell
python -c "import falconpy; print(falconpy.__version__)"
python -c "import openpyxl; print(openpyxl.__version__)"
```

Si ambos comandos imprimen una version, el ambiente ya esta listo para generar el reporte.

#### 6. Preparar variables de entorno

Define al menos:

- `FALCON_CLIENT_ID`
- `FALCON_CLIENT_SECRET`
- `FALCON_TARGET_DOMAIN`

Adicional recomendado para una entrega formal:

- `FALCON_DELIVERABLE_NAME`

Importante:

- revisa `FALCON_DELIVERABLE_NAME` en cada cliente igual que `FALCON_TARGET_DOMAIN`
- no reutilices el mismo nombre comercial entre clientes distintos
- en desarrollo tambien conviene dejarlo correcto para validar desde temprano el nombre final del entregable

Variables recomendadas para una corrida normal:

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

#### 7. Ejecutar el pipeline

Con el entorno virtual activo:

```powershell
python main.py
```

O directamente, sin activar la `.venv`:

```powershell
.venv\Scripts\python.exe main.py
```

#### 8. Validar el resultado

Al finalizar, revisa:

1. el Excel final en la raiz del proyecto
2. la consola para confirmar si hubo `Parser errors`, `Structure issues` o `Requires review`
3. las hojas `Resumen Ejecutivo`, `Plan de Atencion`, `Riesgos Prioritarios`, `Entidades Criticas` y `Detalle Operativo`

#### 9. Cerrar sesion o limpiar contexto antes de cambiar de cliente

Si el equipo se usa como MSSP para varios tenants, limpia las variables de entorno o abre una consola nueva antes de correr un cliente distinto.

</details>

## Instalacion rapida

Si la maquina ya tiene Python y Git, el flujo corto de desarrollo es:

```powershell
git clone <URL_DEL_REPOSITORIO>
cd Identity_Report
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python main.py
```

## Permisos de API en CrowdStrike

Para este proyecto, el API client debe tener al menos estos permisos:

- `Identity Protection Assessment = Read`
- `Identity Protection Detections = Read`
- `Identity Protection Enforcement = Read`
- `Identity Protection Entities = Read`
- `Identity Protection GraphQL = Write`
- `Identity Protection Health = Read`
- `Identity Protection on-premise enablement = Read`
- `Identity Protection Policy Rules = Read`
- `Identity Protection Timeline = Read`

Importante:

- el permiso clave para las consultas GraphQL es `Identity Protection GraphQL = Write`
- aunque la consulta sea de lectura, CrowdStrike exige ese scope para el endpoint GraphQL de Identity Protection

## Configuracion

El proyecto usa variables de entorno.

### Variables obligatorias

- `FALCON_CLIENT_ID`
- `FALCON_CLIENT_SECRET`
- `FALCON_TARGET_DOMAIN`

### Variables opcionales

- `FALCON_DELIVERABLE_NAME`
- `FALCON_PAGE_SIZE`
- `FALCON_OUTPUT_DIR`
- `FALCON_REPORT_NAME`
- `FALCON_SAMPLE_LIMIT_PER_RISK`
- `FALCON_BASE_URL`
- `FALCON_ARTIFACT_MODE`

### `.env.example`

Se incluye un archivo `.env.example` como plantilla de referencia.

Importante:

- el proyecto no carga automaticamente archivos `.env`
- debes exportar las variables en tu sesion PowerShell antes de ejecutar

### Recomendacion para `FALCON_BASE_URL`

Usa la URL API de tu region, no la URL de consola.

Ejemplos validos:

- `https://api.crowdstrike.com`
- `https://api.us-2.crowdstrike.com`

El proyecto convierte esa base automaticamente a la URL de consola correcta para los enlaces Falcon del Excel:

- `https://api.crowdstrike.com` -> `https://falcon.crowdstrike.com`
- `https://api.us-2.crowdstrike.com` -> `https://falcon.us-2.crowdstrike.com`

### Recomendacion para `FALCON_DELIVERABLE_NAME`

Esta variable controla el nombre oficial del Excel final orientado al cliente.

Importante:

- debes revisarla y cambiarla en cada cliente igual que `FALCON_TARGET_DOMAIN`
- no conviene dejar valores genericos como `Cliente`, `Test`, `Demo` o similares
- en entorno MSSP, este valor debe tratarse como parte de la identidad del entregable

Recomendacion:

- usar preferiblemente solo el nombre corto del cliente o del entregable
- evitar palabras como `final`, `draft`, `test` o timestamps manuales
- evitar repetir `Identity_Risk_Assessment` si ya quieres que el proyecto lo agregue por ti
- pensar el valor como la etiqueta comercial del entregable

Ejemplos validos:

- `ACME`
- `Cliente_XYZ`
- `VADER_LOCAL`

El proyecto construye por defecto nombres como:

- `Identity_Risk_Assessment_ACME_2026-04-20.xlsx`

Si prefieres pasar un nombre ya completo, el proyecto intentara respetarlo sin duplicar el prefijo. Por ejemplo:

- `FALCON_DELIVERABLE_NAME=Cliente_Identity_Risk_Assessment`
- salida: `Cliente_Identity_Risk_Assessment_2026-04-20.xlsx`

Si no defines `FALCON_DELIVERABLE_NAME`, el proyecto usara `FALCON_TARGET_DOMAIN` como fallback.

Mala practica:

- dejar `FALCON_TARGET_DOMAIN` apuntando a un cliente y `FALCON_DELIVERABLE_NAME` con el nombre de otro
- reutilizar el mismo `FALCON_DELIVERABLE_NAME` para todos los clientes
- usar placeholders genericos del archivo `.env.example` en una corrida real

### Ejemplo en PowerShell

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

## Uso

Una vez configuradas las variables:

```powershell
python main.py
```

## Flujo funcional

El pipeline sigue este orden:

1. `Discovery`: detecta todos los `riskFactors.type` del dominio.
2. `Inventory`: cuenta frecuencia y arma inventario de riesgos.
3. `Parser selection`: decide si usar parser especifico, especializado o unknown.
4. `Detail extraction`: obtiene el detalle por GraphQL con paginacion automatica.
5. `Parsing`: transforma la data raw en filas tecnicas legibles.
6. `Correlation`: agrega cruces por entidad para ver multiples riesgos relacionados.
7. `Audit`: registra riesgos no soportados, errores y problemas estructurales.
8. `Reporting`: exporta JSON, CSV y Excel.

## Arquitectura interna

El proyecto esta organizado por responsabilidad para reducir acoplamiento entre consulta, parseo, auditoria y salida final.

- `config.py`
  Carga y valida configuracion desde variables de entorno.
- `queries.py`
  Define las consultas GraphQL de discovery y detalle.
- `discovery.py`
  Ejecuta GraphQL con FalconPy y pagina automaticamente hasta agotar resultados.
- `risk_catalog.py`
  Centraliza metadata base de riesgos: titulo, dominio de atencion, resumen tecnico, impacto y remediacion.
- `parser_registry.py`
  Decide que parser usar para cada `risk_type`.
- `parsers.py`
  Transforma payloads de CrowdStrike en filas tecnicas y rutas de ataque.
- `audit.py`
  Registra tipos desconocidos, errores de parser, issues de estructura y muestras raw.
- `analytics.py`
  Construye correlacion por entidad y agregados para la portada ejecutiva.
- `actionability.py`
  Calcula prioridad de revision, nivel de accionabilidad y siguiente paso sugerido.
- `reporting.py`
  Guarda JSON/CSV, genera el workbook de Excel y aplica retencion de artefactos.
- `utils.py`
  Reune helpers de IO, enlaces Falcon y salida visual en consola.

Orden de ejecucion resumido:

1. `main.py` carga configuracion
2. `discovery.py` hace discovery e inventario
3. `discovery.py` hace detail extraction
4. `parsers.py` interpreta riesgos
5. `analytics.py` y `actionability.py` enriquecen filas
6. `audit.py` arma evidencias de soporte
7. `reporting.py` produce CSV/JSON/Excel final

## Organizacion de salidas

El proyecto separa las salidas en dos niveles:

### 1. Artefactos de trabajo

Se guardan dentro de:

```text
output/runs/<report_name>_<timestamp>/
```

Aqui quedan:

- `*_discovery_raw.json`
- `*_detail_raw.json`
- `*_risk_inventory.csv`
- `*_parser_inventory.csv`
- `*_parsed_risks.csv`
- `*_attack_paths.csv`
- `*_unknown_risk_types.csv`
- `*_parser_errors.csv`
- `*_structure_issues.csv`
- `*_raw_samples_overview.csv`
- `*_raw_samples.json`

Estos archivos sirven como trazabilidad tecnica, auditoria y soporte para evolucionar el parser.

### 2. Reporte final

El Excel final se genera fuera de `output/`, en la raiz del proyecto, con un nombre profesional:

```text
Identity_Risk_Assessment_<deliverable_name>_<YYYY-MM-DD>.xlsx
```

Esto permite:

- identificar rapidamente el reporte entregable con un nombre apto para cliente;
- conservar multiples corridas sin sobreescritura mediante versionado automatico;
- separar el entregable del material intermedio de analisis.

Si ya existe un archivo con el mismo nombre para la misma fecha, el proyecto genera:

```text
Identity_Risk_Assessment_<deliverable_name>_<YYYY-MM-DD>_v2.xlsx
Identity_Risk_Assessment_<deliverable_name>_<YYYY-MM-DD>_v3.xlsx
```

Esto evita sobreescritura sin obligarte a exponer timestamps tecnicos en el nombre del entregable.

<details>
<summary><strong>Retencion de artefactos sensibles</strong></summary>

## Retencion de artefactos sensibles

El comportamiento se controla con `FALCON_ARTIFACT_MODE`.

Valores soportados:

- `final_only`
- `standard`
- `debug`

### `final_only`

Modo recomendado para operacion MSSP.

Comportamiento:

- genera el Excel final en la raiz del proyecto
- elimina la carpeta de artefactos intermedios de la corrida
- no conserva JSON ni CSV tecnicos al finalizar

Uso recomendado:

- ejecucion normal para entrega de reporte a cliente
- ambientes donde no se desea persistir evidencia sensible del tenant

### `standard`

Modo intermedio.

Comportamiento:

- conserva la carpeta `output/runs/<corrida>/`
- elimina artefactos raw sensibles
- conserva CSV tecnicos y archivos utiles para revision operativa

Archivos purgados en este modo:

- `*_discovery_raw.json`
- `*_detail_raw.json`
- `*_raw_samples.json`

Uso recomendado:

- revision tecnica interna
- validacion de resultados sin retener payload raw completo

### `debug`

Modo de desarrollo.

Comportamiento:

- conserva todos los artefactos de la corrida
- deja disponible el material necesario para depurar parsers o validar cambios estructurales

Uso recomendado:

- evolucion del proyecto
- investigacion de errores
- incorporacion de nuevos parsers

### Recomendacion operativa

En un entorno MSSP, la recomendacion por defecto es:

```powershell
$env:FALCON_ARTIFACT_MODE="final_only"
```

Usa `debug` solo cuando realmente necesites investigar un fallo o construir soporte para riesgos nuevos.

</details>

## Nota sobre `output/`

La carpeta `output/` no necesita existir en el repositorio.

El proyecto la crea automaticamente en tiempo de ejecucion usando `ensure_output_dir()` en `utils.py`. Si alguien clona el repositorio sin esa carpeta, el pipeline sigue funcionando normalmente y la genera al primer `python main.py`.

## Hojas del Excel

El workbook final esta optimizado para operacion MSSP y revision con cliente. Las hojas visibles se enfocan en priorizacion, accion y lectura clara, mientras que la trazabilidad interna queda en CSV/JSON cuando el modo de artefactos lo permite.

Dependiendo de la corrida y de los datos encontrados, el workbook puede incluir:

- `Resumen Ejecutivo`
- `Plan de Atencion`
- `Riesgos Prioritarios`
- `Entidades Criticas`
- `Rutas de Ataque` solo si hay datos de attack path
- `Resumen por Riesgo`
- `Detalle Operativo`

Descripcion resumida:

- `Resumen Ejecutivo`: KPIs, focos principales, acciones sugeridas y lectura rapida para decision.
- `Plan de Atencion`: vista principal para analista/MSSP con entidad, prioridad, accionabilidad, estado sugerido, accion recomendada, impacto, evidencia y enlace Falcon.
- `Riesgos Prioritarios`: riesgos agregados por volumen, dominio de atencion, porcentaje, criticidad y concentracion observada.
- `Entidades Criticas`: entidades con correlacion de multiples riesgos, severidad mas alta y enlace Falcon.
- `Rutas de Ataque`: rutas observadas cuando CrowdStrike devuelve datos suficientes para construirlas.
- `Resumen por Riesgo`: inventario agregado por `risk_type`, titulo, dominio de atencion, cantidad y porcentaje.
- `Detalle Operativo`: detalle tecnico necesario para revisar y remediar sin exponer columnas internas del parser.

Importante:

- El Excel final ya no muestra hojas de auditoria interna ni hojas duplicadas por dominio de atencion.
- `Auditoria - Sin Parser`, `Auditoria - Errores`, muestras raw y campos de parser se conservan solo como artefactos tecnicos cuando `FALCON_ARTIFACT_MODE` permite conservarlos.
- La hoja oculta `_chart_data` puede existir como soporte interno para graficos y no debe compartirse como vista de analisis.

## Dominios de atencion

Los dominios de atencion del reporte salen del campo interno `family` definido en `risk_catalog.py` para cada `risk_type` soportado. El nombre interno se conserva por compatibilidad con el codigo y los CSV, pero en el Excel y la documentacion se presenta como `Dominio de atencion`.

No es una taxonomia oficial cerrada de CrowdStrike, MITRE, NIST o Microsoft. Es una agrupacion operativa local para ayudar a un analista MSSP a convertir hallazgos de Identity Protection en frentes claros de investigacion, validacion y remediacion.

La fuente primaria del hallazgo sigue siendo CrowdStrike Identity Protection: el `risk_type`, la entidad, la severidad de entidad y los datos del payload. El dominio de atencion es una capa interpretativa local que agrega contexto, priorizacion y lenguaje de remediacion.

### Por que existe esta clasificacion

La clasificacion por dominio de atencion ayuda a:

- convertir muchos `risk_type` tecnicos en frentes de trabajo entendibles;
- explicar a cliente si el problema es higiene de identidad, ciclo de vida, privilegios, endurecimiento, movimiento lateral o actividad adversaria;
- priorizar acciones sin depender solo del volumen;
- agrupar remediaciones que normalmente pertenecen al mismo equipo responsable, por ejemplo IAM, Active Directory, infraestructura, SOC o endpoint.

### Dominios usados por el proyecto

- `Password Hygiene`: debilidades de contrasena, rotacion, reutilizacion y politicas.
- `Identity Hygiene`: cuentas compartidas o patrones que reducen trazabilidad.
- `Account Lifecycle`: cuentas inactivas, obsoletas o con ciclo de vida deficiente.
- `Access Change`: cambios o accesos nuevos que requieren validacion.
- `Behavioral Anomaly`: actividad fuera de linea base o comportamiento esperado.
- `Identity Correlation`: riesgos derivados de relacion entre identidades.
- `Endpoint Exposure`: exposicion indirecta por endpoint riesgoso, compartido o stale.
- `Endpoint Hardening`: configuraciones debiles en endpoints o protocolos.
- `Endpoint Posture`: postura vulnerable o desactualizada del activo asociado.
- `Directory Hardening`: configuraciones de directorio que debilitan integridad o autenticacion.
- `Credential Abuse`: escenarios de abuso o reutilizacion de credenciales.
- `Kerberos Exposure`: superficie relacionada con Kerberos, SPN o KRBTGT.
- `Certificate Exposure`: exposicion por configuracion de AD CS/certificados.
- `Privilege Exposure`: privilegios, cuentas o equipos con impacto elevado.
- `Lateral Movement`: relaciones o rutas que facilitan movimiento lateral.
- `Threat Activity`: senales de actividad adversaria o investigacion activa.
- `Unclassified`: fallback para riesgos nuevos o no catalogados todavia.

### Como debe interpretarlos un analista

Usa el dominio de atencion como orientacion, no como veredicto. La secuencia recomendada es:

1. confirmar el `risk_type` y la entidad en Falcon;
2. usar el dominio de atencion para entender el frente tecnico;
3. revisar la accion recomendada y la evidencia disponible;
4. validar owner, criticidad, uso legitimo y ventana de cambio;
5. ajustar la prioridad si el contexto del cliente cambia el impacto.

Si aparece `Unclassified`, significa que CrowdStrike devolvio un tipo de riesgo que el proyecto todavia no tiene catalogado. En ese caso se debe revisar el payload, confirmar significado operativo y agregar metadata al `risk_catalog.py` antes de usarlo como criterio recurrente.

## Nota sobre severidad

La columna de severidad del workbook representa la `riskScoreSeverity` de la entidad reportada por CrowdStrike, no necesariamente una severidad independiente por cada `riskFactor`.

Para hacerla mas entendible en el Excel:

- `NORMAL` se presenta como `LOW`
- `MEDIUM`, `HIGH` y `CRITICAL` se mantienen

En las hojas de correlacion se usa la misma logica bajo el nombre `Severidad mas alta de entidad`.

## Revision recomendada despues de ejecutar

Orden sugerido para un analista:

1. abrir el archivo `Identity_Risk_Assessment_<deliverable_name>_<YYYY-MM-DD>.xlsx`
2. revisar `Resumen Ejecutivo`
3. trabajar primero `Plan de Atencion`, empezando por `P1` y `Atencion inmediata`
4. revisar `Riesgos Prioritarios` para entender concentracion, volumen y dominio de atencion
5. revisar `Entidades Criticas` para identificar cuentas o activos con riesgo correlacionado
6. revisar `Rutas de Ataque` si la hoja existe
7. usar `Detalle Operativo` para validar evidencia, impacto y accion recomendada antes de remediar

## Guia L1 de atencion

Esta guia esta pensada para analistas L1 de MSSP. El objetivo del L1 no es cerrar la remediacion tecnica por cuenta propia, sino ordenar hallazgos, validar lo basico, documentar evidencia y escalar correctamente.

### Antes de compartir con cliente

No compartas el reporte como entregable final si ocurre cualquiera de estos casos:

- el Excel no se genero o el nombre del archivo no corresponde al cliente;
- `FALCON_TARGET_DOMAIN` o `FALCON_DELIVERABLE_NAME` no corresponden al cliente actual;
- la consola muestra `Parser errors` o `Structure issues` mayores que cero;
- aparece un dominio `Unclassified` o un riesgo que el equipo no ha validado;
- hay dudas sobre si la corrida apunta a la region correcta de CrowdStrike.

Si aparece `Requires review` mayor que cero, no cierres esos casos. Puedes usar el reporte para revision interna, pero las filas afectadas deben ser validadas por L2 antes de presentarlas como conclusion final.

### Flujo de trabajo recomendado

1. Confirmar archivo y cliente:
   abre el Excel generado y valida que el dominio de `Resumen Ejecutivo` sea el cliente correcto.
2. Revisar salud de la corrida:
   en consola valida `Parser errors`, `Structure issues`, `Unknown risk types` y `Requires review`.
3. Priorizar:
   en `Plan de Atencion`, filtra primero `Prioridad de revision = P1` y `Estado sugerido = Atencion inmediata`.
4. Validar en Falcon:
   abre el `Enlace Falcon` de cada fila prioritaria y confirma entidad, tipo de riesgo y contexto visible.
5. Preparar ticket:
   usa `Riesgo`, `Impacto probable`, `Evidencia disponible` y `Accion recomendada` como base del ticket.
6. Revisar concentracion:
   usa `Riesgos Prioritarios` para entender si el problema es masivo o focalizado.
7. Revisar entidades:
   usa `Entidades Criticas` para identificar cuentas o activos que acumulan varios tipos de riesgo.
8. Escalar:
   escala a L2 si el hallazgo es P1, si requiere investigacion guiada, si toca privilegios, Kerberos, AD CS, movimiento lateral o si no entiendes la evidencia.

### Como leer prioridad y accionabilidad

- `P1`: atender primero. Crear ticket y escalar a L2 si requiere investigacion, privilegios, movimiento lateral o cambios sensibles.
- `P2`: validar contexto en Falcon y preparar plan de remediacion. Escalar si el owner, impacto o evidencia no son claros.
- `P3`: tratar como mejora operativa o higiene. Puede agruparse con otros hallazgos del mismo dominio.
- `Accion directa`: el hallazgo normalmente permite una remediacion concreta, pero el cliente debe confirmar owner, ventana y posible impacto.
- `Validacion en Falcon`: no remediar sin confirmar entidad, contraparte, fecha, origen o contexto adicional.
- `Investigacion guiada`: no cerrar en L1; requiere investigacion o confirmacion de L2/SOC/Identity.

### Cuando pedir apoyo

Pide apoyo a L2 o al responsable interno si:

- el enlace Falcon no abre o apunta a una region inesperada;
- la entidad es privilegiada, administrativa, de servicio o critica;
- hay `Stealthy privileges`, `KRBTGT`, `AD CS`, `Pass-the-hash`, `Lateral Movement` o `Attack Path`;
- la accion recomendada implica deshabilitar cuentas, cambiar politicas, rotar credenciales sensibles o tocar controladores de dominio;
- el cliente pregunta si el hallazgo es incidente confirmado;
- el reporte muestra datos que no coinciden con el tenant o el alcance esperado.

### Plantilla corta para ticket MSSP

```text
Titulo:
[Identity Protection] <Riesgo> en <Entidad> - <Prioridad>

Resumen:
Se detecto <Riesgo> sobre <Entidad>. Dominio de atencion: <Dominio de atencion>.

Impacto probable:
<Impacto probable del Excel>

Evidencia:
<Evidencia disponible del Excel>
Enlace Falcon: <Enlace Falcon>

Accion recomendada:
<Accion recomendada del Excel>

Validacion L1:
- Cliente/dominio confirmado: Si/No
- Entidad revisada en Falcon: Si/No
- Requiere L2: Si/No
- Motivo de escalamiento: <motivo si aplica>
```

### Plantilla corta para comentario al cliente

```text
Durante la revision de Identity Protection se identificaron hallazgos priorizados por impacto operativo y concentracion.
Se recomienda iniciar por los elementos P1 del Plan de Atencion, validar owner y uso legitimo de las entidades afectadas, y coordinar ventanas de remediacion para las acciones que impliquen cambios de cuenta, privilegios o configuracion.
Los hallazgos marcados como investigacion o validacion requieren confirmacion adicional en Falcon antes de considerarse cerrados.
```

<details>
<summary><strong>Cambio de cliente en entorno MSSP</strong></summary>

## Cambio de cliente en entorno MSSP

Si este proyecto se usa para varios clientes, es importante no reutilizar por accidente configuracion del cliente anterior.

Buenas practicas:

- usar una sesion PowerShell nueva por cliente;
- validar siempre `FALCON_TARGET_DOMAIN` antes de ejecutar;
- validar siempre `FALCON_DELIVERABLE_NAME` antes de ejecutar;
- revisar `FALCON_BASE_URL` segun la region correcta;
- no reutilizar archivos de `output/runs/` como insumo de otro cliente;
- no compartir ni versionar resultados reales del tenant.

Si necesitas conservar artefactos para debugging, cambia temporalmente a:

```powershell
$env:FALCON_ARTIFACT_MODE="debug"
```

y vuelve a `final_only` antes de una corrida operativa normal.

### Limpiar variables de entorno antes de cambiar de cliente

En PowerShell puedes limpiar la sesion actual asi:

```powershell
Remove-Item Env:FALCON_CLIENT_ID -ErrorAction SilentlyContinue
Remove-Item Env:FALCON_CLIENT_SECRET -ErrorAction SilentlyContinue
Remove-Item Env:FALCON_TARGET_DOMAIN -ErrorAction SilentlyContinue
Remove-Item Env:FALCON_DELIVERABLE_NAME -ErrorAction SilentlyContinue
Remove-Item Env:FALCON_PAGE_SIZE -ErrorAction SilentlyContinue
Remove-Item Env:FALCON_OUTPUT_DIR -ErrorAction SilentlyContinue
Remove-Item Env:FALCON_REPORT_NAME -ErrorAction SilentlyContinue
Remove-Item Env:FALCON_SAMPLE_LIMIT_PER_RISK -ErrorAction SilentlyContinue
Remove-Item Env:FALCON_BASE_URL -ErrorAction SilentlyContinue
```

Luego cargas las variables del siguiente cliente y vuelves a ejecutar.

Alternativa recomendada:

- cerrar la consola actual
- abrir una nueva sesion PowerShell
- volver a exportar solo las variables del cliente que vas a procesar

</details>

<details>
<summary><strong>Troubleshooting</strong></summary>

## Troubleshooting

### Error por variables faltantes

Configura las variables obligatorias antes de ejecutar:

```powershell
$env:FALCON_CLIENT_ID="..."
$env:FALCON_CLIENT_SECRET="..."
$env:FALCON_TARGET_DOMAIN="..."
```

### Error: falta `falconpy`

```powershell
pip install -r requirements.txt
```

### Error: no se genera el Excel

Verifica que `openpyxl` este instalado:

```powershell
pip install openpyxl
```

### Error: la activacion de `.venv` esta bloqueada

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.venv\Scripts\Activate.ps1
```

### Error: `python` no apunta al entorno virtual correcto

Ejecuta el script con el interprete de la `.venv`:

```powershell
.venv\Scripts\python.exe main.py
```

</details>

<details>
<summary><strong>Referencias tecnicas para analistas</strong></summary>

## Referencias tecnicas para analistas

Esta seccion no forma parte del pipeline ni del reporte final. Es material de apoyo para que un analista entienda por que ciertos dominios de atencion o hallazgos son relevantes en identidad, autenticacion, privilegios y movimiento lateral.

Los dominios de atencion usados por el proyecto son una agrupacion operativa local. No deben presentarse como un estandar oficial. Lo oficial es el hallazgo que devuelve CrowdStrike y, para fundamentar la atencion, las fuentes tecnicas de referencia como Microsoft Learn, MITRE ATT&CK y NIST. Los dominios ayudan a ordenar el trabajo, conectar hallazgos con responsables tecnicos y explicar impacto de forma clara.

Los enlaces de esta seccion fueron revisados durante el mantenimiento del proyecto y se priorizaron fuentes con buen valor operativo para analistas:

- Microsoft Learn: para entender tecnologia, controles y postura recomendada
- MITRE ATT&CK: para mapear hallazgos a tacticas y tecnicas de adversario
- NIST: para fundamentos de identidad y autenticacion
- SpecterOps: para AD CS, Kerberos ofensivo y abuso de identidad en Active Directory

### Ruta recomendada para analistas menos experimentados

Si no sabes por donde empezar, usa este orden:

1. leer `Windows Authentication Overview` para entender el terreno base
2. ubicar el dominio de atencion del hallazgo en la lista de abajo
3. leer primero la referencia de Microsoft Learn o NIST
4. luego abrir ATT&CK si el hallazgo sugiere abuso o actividad adversaria
5. usar SpecterOps cuando el hallazgo toque AD CS, Kerberos o escalamiento en Active Directory

### Mapa rapido de ayuda por dominio

Usa esta tabla cuando no sepas por donde empezar o que referencia consultar primero.

| Dominio de atencion | Que significa para L1 | Primera referencia | Escalar si ves |
| --- | --- | --- | --- |
| `Password Hygiene` | Problemas de contrasena, rotacion, politica o reutilizacion. | Microsoft Entra Password Protection | Cuentas privilegiadas, cuentas de servicio o cambios masivos de politica. |
| `Identity Hygiene` | Identidades compartidas o baja trazabilidad. | Windows Authentication Overview | Cuentas usadas por varias personas, servicios criticos o falta de owner. |
| `Account Lifecycle` | Cuentas inactivas, obsoletas o con uso inesperado. | Microsoft Entra ID Governance | Cuenta administrativa, servicio productivo o duda sobre deshabilitar. |
| `Access Change` | Acceso nuevo o cambio que requiere confirmacion. | Identity Governance / Lifecycle Workflows | Acceso a servidores criticos o actividad fuera de horario. |
| `Behavioral Anomaly` | Comportamiento fuera de linea base. | MITRE ATT&CK Enterprise tactics | Actividad repetida, origen sospechoso o posible incidente. |
| `Endpoint Exposure` | Riesgo indirecto por endpoint compartido, stale o riesgoso. | Windows Authentication Overview | Endpoint no gestionado, compartido o usado por privilegios. |
| `Endpoint Hardening` | Configuracion debil en endpoint o protocolo. | SMB signing / NTLM overview | Cambios que afecten compatibilidad o sistemas heredados. |
| `Endpoint Posture` | Sistema vulnerable o desactualizado. | Referencias internas de patching del cliente | Activo critico, servidor o sistema sin owner claro. |
| `Directory Hardening` | Debilidades en LDAP, LDAPS o directorio. | LDAP signing for AD DS | Controladores de dominio, relay o cambios de GPO. |
| `Credential Abuse` | Riesgo de abuso de credenciales. | MITRE Credential Access | Pass-the-hash, brute force, robo de credenciales o cuenta privilegiada. |
| `Kerberos Exposure` | Exposicion relacionada con Kerberos, SPN o KRBTGT. | Kerberos authentication overview | KRBTGT, SPN en cuenta sensible o dudas sobre rotacion. |
| `Certificate Exposure` | Riesgo por AD CS o plantillas de certificados. | AD CS overview / SpecterOps | Cualquier cambio en plantillas, enrollment o autenticacion por certificado. |
| `Privilege Exposure` | Privilegios o cuentas con impacto alto. | Attractive Accounts for Credential Theft | Privilegios discretos, administrador, endpoint no gestionado o cuenta critica. |
| `Lateral Movement` | Relaciones o rutas que habilitan movimiento lateral. | MITRE Lateral Movement | Attack path, admin share, sesiones privilegiadas o activo critico. |
| `Threat Activity` | Senales de actividad adversaria o investigacion activa. | MITRE ATT&CK Enterprise tactics | Posible incidente, reconocimiento, RPC anomalo, scanning o brute force. |
| `Unclassified` | El proyecto aun no tiene clasificacion para ese riesgo. | Revisar Falcon y escalar internamente | Siempre escalar antes de presentarlo como conclusion. |

### Como elegir la referencia correcta

- Si el hallazgo es de postura o configuracion, empieza por Microsoft Learn.
- Si el hallazgo parece actividad adversaria, usa MITRE ATT&CK para explicar tactica e impacto.
- Si el hallazgo es de autenticacion fuerte o gobierno de identidad, usa NIST y Microsoft Learn.
- Si el hallazgo toca AD CS, Kerberos avanzado o escalamiento en Active Directory, usa SpecterOps y escala a L2.
- Si no entiendes el riesgo despues de leer la referencia sugerida, no improvises: documenta lo visto en Falcon y pide apoyo.

### Fundamentos de identidad y autenticacion

- Windows Authentication Overview  
  https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/windows-authentication-overview
- NIST SP 800-63-4: Digital Identity Guidelines  
  https://www.nist.gov/publications/nist-sp-800-63-4-digital-identity-guidelines
- Microsoft Learn: Phishing-resistant MFA  
  https://learn.microsoft.com/en-us/security/zero-trust/sfi/phishing-resistant-mfa

Uso sugerido:

- entender autenticacion, Kerberos, NTLM, MFA y conceptos base antes de interpretar riesgos especificos
- usar NIST como referencia cuando necesites justificar por que autenticacion fuerte y gobierno de identidad importan

### Password Hygiene / Identity Hygiene

- Microsoft Entra Password Protection  
  https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad
- Microsoft Entra Password Protection for AD DS  
  https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad-on-premises
- MITRE ATT&CK - Password Spraying (`T1110.003`)  
  https://attack.mitre.org/techniques/T1110/003/
- MITRE ATT&CK - Credential Stuffing (`T1110.004`)  
  https://attack.mitre.org/techniques/T1110/004/

Uso sugerido:

- interpretar `WEAK_PASSWORD`, `WEAK_PASSWORD_POLICY`, `DUPLICATE_PASSWORD`, `INSUFFICIENT_PASSWORD_ROTATION`, `SHARED_USER`
- explicar por que contrasenas debiles, reutilizadas o compartidas facilitan password spraying, stuffing y compromiso de cuentas

### Account Lifecycle / Access Change / Behavioral Anomaly

- Microsoft Entra ID Governance overview  
  https://learn.microsoft.com/en-us/entra/id-governance/identity-governance-overview
- What are Lifecycle Workflows?  
  https://learn.microsoft.com/en-us/entra/id-governance/what-are-lifecycle-workflows
- Microsoft Learn: Phishing-resistant MFA  
  https://learn.microsoft.com/en-us/security/zero-trust/sfi/phishing-resistant-mfa

Uso sugerido:

- interpretar `INACTIVE_ACCOUNT`, `STALE_ACCOUNT`, `STALE_ACCOUNT_USAGE`, `NEW_SERVER_ACCESS`, `DAILY_VOLUME_ANOMALY`
- conectar los hallazgos con procesos Joiner / Mover / Leaver, excepciones de acceso y falta de gobierno sobre cambios de identidad

### Endpoint Hardening / Directory Hardening

- SMB signing overview  
  https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview
- LDAP signing for AD DS  
  https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing
- Windows Authentication Overview  
  https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/windows-authentication-overview

Uso sugerido:

- interpretar `SMB_SIGNING_DISABLED`, `LDAP_SIGNING_DISABLED`, `LDAPS_CHANNEL_BINDING`
- apoyar conversaciones con AD, infraestructura y hardening sobre relay, integridad de trafico y autenticacion heredada

### Kerberos Exposure / Credential Abuse / Lateral Movement

- Kerberos authentication overview  
  https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview
- NTLM overview  
  https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview
- MITRE ATT&CK - Steal or Forge Kerberos Tickets (`T1558`)  
  https://attack.mitre.org/techniques/T1558/
- MITRE ATT&CK - Lateral Movement (`TA0008`)  
  https://attack.mitre.org/tactics/TA0008/

Uso sugerido:

- interpretar `HAS_SPNS`, `KRBTGT_AGED_PASSWORD`, `PASS_THE_HASH`, `LATERAL_MOVEMENT`, `HAS_ATTACK_PATH`, `NTLM_MOVEMENTS`
- relacionar el hallazgo con tickets Kerberos, abuso de credenciales, rutas de ataque y expansion del compromiso

### Privilege Exposure

- Microsoft Learn: Phishing-resistant MFA  
  https://learn.microsoft.com/en-us/security/zero-trust/sfi/phishing-resistant-mfa
- Attractive Accounts for Credential Theft  
  https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/attractive-accounts-for-credential-theft
- MITRE ATT&CK - Privilege Escalation (`TA0004`)  
  https://attack.mitre.org/tactics/TA0004/

Uso sugerido:

- interpretar `STEALTHY_PRIVILEGES`, `PRIVILEGED_MACHINE`, `PRIVILEGED_USER_USING_UNMANAGED_ENDPOINT`, `SHARED_ENDPOINT_USED_BY_PRIVILEGED_USER`
- justificar por que cuentas privilegiadas, endpoints no gestionados y privilegios discretos deben tratarse como prioridad alta

### Certificate Exposure / AD CS

- Active Directory Certificate Services overview  
  https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview
- SpecterOps: Certified Pre-Owned  
  https://specterops.io/blog/2021/06/17/certified-pre-owned/

Uso sugerido:

- interpretar `CERTIFICATE_TEMPLATE_ALLOWS_AUTHENTICATION_AS_ANY_DOMAIN_USER`
- entender por que una mala configuracion en AD CS puede terminar en autenticacion indebida, persistencia o escalamiento

### Threat Activity / Deteccion / Contexto de adversario

- MITRE ATT&CK Enterprise tactics  
  https://attack.mitre.org/tactics/enterprise/
- MITRE ATT&CK - Credential Access (`TA0006`)  
  https://attack.mitre.org/tactics/TA0006/
- MITRE ATT&CK - Lateral Movement (`TA0008`)  
  https://attack.mitre.org/tactics/TA0008/
- MITRE ATT&CK - Privilege Escalation (`TA0004`)  
  https://attack.mitre.org/tactics/TA0004/

Uso sugerido:

- dar contexto a `CREDENTIAL_THEFT`, `CREDENTIAL_SCANNING`, `PASSWORD_BRUTE_FORCE`, `LDAP_RECONNAISSANCE`, `ANOMALOUS_RPC`, `DAILY_VOLUME_ANOMALY`
- mapear el hallazgo a tacticas y tecnicas ATT&CK para explicarlo mejor a analistas, clientes o equipos de respuesta

### Nota practica para quien redacta el reporte

Una forma simple de usar estas referencias durante el analisis es:

1. identificar si el hallazgo es de postura, gobierno, privilegio o actividad adversaria
2. leer la referencia funcional primero
3. usar ATT&CK para contextualizar impacto o cadena de ataque
4. volver al reporte y traducir el hallazgo a lenguaje operativo:
   riesgo, por que importa, que podria habilitar y que deberia validar el cliente

</details>

## Nota para analistas

El reporte no reemplaza la validacion en Falcon ni la investigacion del equipo de identidad. Su objetivo es:

- priorizar
- correlacionar
- resumir
- y convertir hallazgos de Identity Protection en una base tecnica accionable

Cuando un hallazgo indique que no hay `detalle tecnico adicional en este payload`, debe interpretarse como:

- hallazgo valido reportado por CrowdStrike
- contexto tecnico limitado en la consulta actual
- necesidad de complementar con Falcon u otras fuentes antes de cerrar remediacion

## Limitaciones conocidas

- El proyecto depende del esquema actual que devuelve CrowdStrike Identity Protection por GraphQL.
- No todos los riesgos devuelven el mismo nivel de detalle; `HAS_ATTACK_PATH` suele ser mas rico que otros tipos.
- Para varios riesgos, CrowdStrike solo devuelve `type`, `__typename` y la severidad de entidad, por lo que parte del contexto sigue siendo interpretativo.
- La severidad mostrada en Excel corresponde a severidad de entidad, no necesariamente a una severidad independiente por cada `riskFactor`.
- Si CrowdStrike cambia `__typename`, campos o estructura de `attackPath`, el pipeline puede seguir funcionando, pero aumentaran los hallazgos en auditoria o bajara la calidad del parseo.
- El proyecto prioriza continuidad del pipeline sobre fallo duro: ante riesgos nuevos o estructuras no soportadas, registra auditoria y continua.

### Error HTTP 403 `scope not permitted`

Valida que el API client tenga:

- `Identity Protection GraphQL = Write`

### Error de links Falcon incorrectos

Verifica que `FALCON_BASE_URL` sea una API URL regional, por ejemplo:

- `https://api.crowdstrike.com`
- `https://api.us-2.crowdstrike.com`

## Consideraciones importantes

- el proyecto no depende del export manual desde la consola web
- la paginacion se hace automaticamente por `pageInfo.hasNextPage` y `pageInfo.endCursor`
- el dominio objetivo no va hardcodeado en el codigo
- si aparece un riesgo nuevo, el pipeline no se rompe: se registra en auditoria y continua
- el repositorio no debe incluir resultados reales del tenant por confidencialidad

## Mejoras futuras

- agregar carga automatica de `.env` si en algun momento se desea ese flujo
- agregar tests unitarios para parsers y validaciones
- enriquecer aun mas los parsers especializados
- soportar multiples dominios o ejecucion por lote
- generar PDF o documento ejecutivo adicional
