# Generador de Reporte de Riesgos de Identity Protection desde CrowdStrike

Pipeline en Python para consultar CrowdStrike Identity Protection por GraphQL usando FalconPy, descubrir riesgos en un dominio, clasificarlos, aplicar parsers por tipo y generar salidas técnicas para análisis y reporting.

## Objetivo

Este proyecto automatiza el flujo de trabajo para:

- descubrir todos los `riskFactors.type` presentes en un dominio;
- contar y clasificar riesgos;
- seleccionar el parser adecuado por tipo;
- parsear riesgos complejos y simples;
- registrar auditoría de casos no soportados o con errores;
- generar artefactos intermedios en JSON/CSV;
- generar un Excel técnico final.

## Estado actual

Actualmente el proyecto soporta:

- `discovery` de tipos de riesgo;
- `detail extraction` con paginación automática;
- parser específico para `HAS_ATTACK_PATH`;
- parser genérico para riesgos simples;
- parser `unknown` para riesgos nuevos o no contemplados;
- auditoría de `unknown risk types`, `parser errors`, `structure issues` y `raw samples`;
- exportación a JSON, CSV y Excel técnico.

## Estructura del proyecto

```text
Identity_Report/
├── main.py
├── config.py
├── queries.py
├── discovery.py
├── parser_registry.py
├── parsers.py
├── audit.py
├── reporting.py
├── utils.py
├── requirements.txt
├── README.md
└── output/
```

## Requisitos

- Python 3.10 o superior
- credenciales de CrowdStrike Falcon con acceso a Identity Protection GraphQL
- dependencias del proyecto:

```text
crowdstrike-falconpy
openpyxl
```

## Instalación

### 1. Clonar el repositorio

```powershell
git clone <URL_DEL_REPOSITORIO>
cd Identity_Report
```

### 2. Crear entorno virtual

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Instalar dependencias

```powershell
pip install -r requirements.txt
```

## Configuración

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

### Ejemplo en PowerShell

```powershell
$env:FALCON_CLIENT_ID="TU_CLIENT_ID"
$env:FALCON_CLIENT_SECRET="TU_CLIENT_SECRET"
$env:FALCON_TARGET_DOMAIN="cliente.local"
$env:FALCON_PAGE_SIZE="1000"
$env:FALCON_OUTPUT_DIR="output"
$env:FALCON_REPORT_NAME="identity_risk_report"
$env:FALCON_SAMPLE_LIMIT_PER_RISK="3"
$env:FALCON_BASE_URL="https://falcon.crowdstrike.com"
```

## Ejecución

Una vez configuradas las variables:

```powershell
python main.py
```

## Flujo funcional

El pipeline sigue este orden:

1. `Discovery`: detecta todos los `riskFactors.type` del dominio.
2. `Inventory`: cuenta frecuencia y arma inventario de riesgos.
3. `Parser selection`: decide si usar parser específico, genérico o unknown.
4. `Detail extraction`: obtiene información más rica con una segunda query.
5. `Parsing`: transforma la data raw en filas legibles.
6. `Audit`: registra riesgos no soportados, errores y problemas estructurales.
7. `Reporting`: exporta JSON, CSV y Excel.

## Salidas generadas

Los archivos se guardan en la carpeta configurada por `FALCON_OUTPUT_DIR`.

### Archivos esperados

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
- `*_technical_report.xlsx`

### Hojas del Excel técnico

- `Risk Summary`
- `Parsed Risks`
- `Attack Paths`
- `Audit - Unknown`
- `Audit - Errors`

## Parsers

### Parser específico

- `HAS_ATTACK_PATH` -> `attack_path`

### Parser genérico

Se usa para riesgos simples o de estructura no compleja, por ejemplo:

- `WEAK_PASSWORD_POLICY`
- `WEAK_PASSWORD`
- `DUPLICATE_PASSWORD`
- `INACTIVE_ACCOUNT`
- `STALE_ACCOUNT`
- `STALE_ACCOUNT_USAGE`
- `INSUFFICIENT_PASSWORD_ROTATION`
- `SMB_SIGNING_DISABLED`
- `LDAP_SIGNING_DISABLED`
- `LDAPS_CHANNEL_BINDING`
- `VULNERABLE_OS`
- `CREDENTIAL_THEFT`
- `CREDENTIAL_SCANNING`
- `PASSWORD_BRUTE_FORCE`
- `LDAP_RECONNAISSANCE`
- `NEW_SERVER_ACCESS`
- `SHARED_USER`
- `SHARED_ENDPOINT`
- `STEALTHY_PRIVILEGES`
- `RISKY_LINKED_ACCOUNT`
- `STALE_HOST_USAGE`

### Parser unknown

Se aplica cuando:

- aparece un tipo de riesgo no registrado;
- no existe parser asignado;
- el riesgo requiere revisión manual futura.

## Auditoría

El módulo `audit.py` registra:

- tipos de riesgo sin parser;
- errores de ejecución de parsers;
- problemas de estructura;
- muestras raw limitadas por tipo.

Esto permite evolucionar el proyecto con base en evidencia real del tenant.

## Consideraciones importantes

- El proyecto no depende del export manual desde la consola web.
- La paginación se hace automáticamente por `pageInfo.hasNextPage` y `pageInfo.endCursor`.
- El dominio objetivo no va hardcodeado en el código.
- Si aparece un riesgo nuevo, el pipeline no debe romperse: se registra en auditoría y continúa.

## Troubleshooting

### Error: falta `falconpy`

Instala dependencias:

```powershell
pip install -r requirements.txt
```

### Error: no se genera el Excel

Verifica que `openpyxl` esté instalado:

```powershell
pip install openpyxl
```

### Error por variables faltantes

Configura las variables obligatorias antes de ejecutar:

```powershell
$env:FALCON_CLIENT_ID="..."
$env:FALCON_CLIENT_SECRET="..."
$env:FALCON_TARGET_DOMAIN="..."
```

## Mejoras futuras

- agregar más parsers específicos por tipo de riesgo;
- enriquecer descripciones técnicas por riesgo;
- generar PDF o documento ejecutivo;
- agregar `.env.example`;
- agregar tests unitarios para parsers y validaciones;
- soportar múltiples dominios o ejecución por lote.

## Publicación en Git

Sí puedo dejarte el repositorio listo para subir a GitHub o GitLab, incluyendo documentación en Markdown y archivos auxiliares.

Desde este entorno no puedo garantizar subirlo a tu remoto porque:

- aquí no está disponible `git` en la terminal actual;
- no tengo acceso automático a tus credenciales o remoto;
- no debo hacer `push` a tu cuenta sin ese acceso configurado.

Pero tú puedes subirlo con este flujo:

```powershell
git init
git add .
git commit -m "Initial commit - Identity Protection risk reporting pipeline"
git branch -M main
git remote add origin <URL_DE_TU_REPO>
git push -u origin main
```

Si quieres, en el siguiente paso te puedo dejar también:

- un `.env.example`;
- un `LICENSE`;
- una plantilla de `CHANGELOG.md`;
- o una versión del `README.md` más ejecutiva para cliente interno.
