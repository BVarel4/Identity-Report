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
- [Nota sobre severidad](#nota-sobre-severidad)
- [Revision recomendada despues de ejecutar](#revision-recomendada-despues-de-ejecutar)
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

Ejemplo recomendado:

```powershell
$env:FALCON_CLIENT_ID="TU_CLIENT_ID"
$env:FALCON_CLIENT_SECRET="TU_CLIENT_SECRET"
$env:FALCON_TARGET_DOMAIN="cliente.local"
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
3. las hojas `Resumen Ejecutivo`, `Rutas de Ataque`, `Correlacion Ciclo Vida` y `Riesgos Parseados`

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

Variables recomendadas para una corrida normal:

```powershell
$env:FALCON_CLIENT_ID="TU_CLIENT_ID"
$env:FALCON_CLIENT_SECRET="TU_CLIENT_SECRET"
$env:FALCON_TARGET_DOMAIN="cliente.local"
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
3. las hojas `Resumen Ejecutivo`, `Rutas de Ataque`, `Correlacion Ciclo Vida` y `Riesgos Parseados`

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

### Ejemplo en PowerShell

```powershell
$env:FALCON_CLIENT_ID="TU_CLIENT_ID"
$env:FALCON_CLIENT_SECRET="TU_CLIENT_SECRET"
$env:FALCON_TARGET_DOMAIN="cliente.local"
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
  Centraliza metadata base de riesgos: titulo, familia, resumen tecnico, impacto y remediacion.
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
Identity_Protection_Report_<dominio>_<timestamp>_FINAL.xlsx
```

Esto permite:

- identificar rapidamente el reporte entregable;
- conservar multiples corridas sin sobreescritura;
- separar el entregable del material intermedio de analisis.

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

Dependiendo de la corrida y de los datos encontrados, el workbook puede incluir:

- `Resumen Ejecutivo`
- `Resumen Riesgos`
- `Riesgos Parseados`
- `Rutas de Ataque`
- `Correlacion Entidades`
- `Correlacion Ciclo Vida`
- `Credenciales Identidad`
- `Ciclo Vida Acceso`
- `Endpoint Directorio`
- `Amenaza Privilegios`
- `Auditoria - Sin Parser`
- `Auditoria - Errores`

Importante:

- `Auditoria - Sin Parser` y `Auditoria - Errores` quedan siempre al final del documento
- estas hojas estan pensadas para mantenimiento del proyecto y evolucion futura del parser

## Nota sobre severidad

La columna de severidad del workbook representa la `riskScoreSeverity` de la entidad reportada por CrowdStrike, no necesariamente una severidad independiente por cada `riskFactor`.

Para hacerla mas entendible en el Excel:

- `NORMAL` se presenta como `LOW`
- `MEDIUM`, `HIGH` y `CRITICAL` se mantienen

En las hojas de correlacion se usa la misma logica bajo el nombre `Severidad mas alta de entidad`.

## Revision recomendada despues de ejecutar

Orden sugerido para un analista:

1. abrir el archivo `Identity_Protection_Report_<dominio>_<timestamp>_FINAL.xlsx`
2. revisar `Resumen Ejecutivo`
3. revisar `Rutas de Ataque`
4. revisar `Correlacion Ciclo Vida`
5. revisar las hojas tematicas por dominio tecnico
6. revisar `Auditoria - Errores` solo si hubo comportamientos no esperados

<details>
<summary><strong>Cambio de cliente en entorno MSSP</strong></summary>

## Cambio de cliente en entorno MSSP

Si este proyecto se usa para varios clientes, es importante no reutilizar por accidente configuracion del cliente anterior.

Buenas practicas:

- usar una sesion PowerShell nueva por cliente;
- validar siempre `FALCON_TARGET_DOMAIN` antes de ejecutar;
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

Esta seccion no forma parte del pipeline ni del reporte final. Es material de apoyo para que un analista entienda por que ciertas familias o hallazgos son relevantes en identidad, autenticacion, privilegios y movimiento lateral.

Los enlaces de esta seccion fueron revisados durante el mantenimiento del proyecto y se priorizaron fuentes con buen valor operativo para analistas:

- Microsoft Learn: para entender tecnologia, controles y postura recomendada
- MITRE ATT&CK: para mapear hallazgos a tacticas y tecnicas de adversario
- NIST: para fundamentos de identidad y autenticacion
- SpecterOps: para AD CS, Kerberos ofensivo y abuso de identidad en Active Directory

### Ruta recomendada para analistas menos experimentados

Si no sabes por donde empezar, usa este orden:

1. leer `Windows Authentication Overview` para entender el terreno base
2. ubicar la familia del hallazgo en la lista de abajo
3. leer primero la referencia de Microsoft Learn o NIST
4. luego abrir ATT&CK si el hallazgo sugiere abuso o actividad adversaria
5. usar SpecterOps cuando el hallazgo toque AD CS, Kerberos o escalamiento en Active Directory

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
