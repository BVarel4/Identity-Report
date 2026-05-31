# Operación en entorno MSSP

Esta guía describe buenas prácticas para ejecutar el proyecto en ambientes MSSP donde se procesan múltiples clientes, dominios o tenants de CrowdStrike.

El objetivo es reducir riesgos de mezcla de información, configuración incorrecta, exposición de artefactos sensibles y entrega de reportes con nombres o dominios equivocados.

---

## Principio principal

Cada corrida debe tratarse como una operación independiente por cliente.

Antes de ejecutar, valida:

- tenant correcto;
- región correcta;
- dominio correcto;
- nombre de entregable correcto;
- modo de artefactos correcto;
- permisos correctos del API Client;
- ubicación de salida esperada.

---

## Variables críticas

| Variable | Riesgo si está mal configurada |
| --- | --- |
| `FALCON_CLIENT_ID` | Consultar el tenant incorrecto o fallar autenticación. |
| `FALCON_CLIENT_SECRET` | Fallar autenticación o exponer credenciales si se almacena mal. |
| `FALCON_TARGET_DOMAIN` | Generar reporte de un dominio incorrecto. |
| `FALCON_DELIVERABLE_NAME` | Crear un Excel con nombre de cliente incorrecto. |
| `FALCON_BASE_URL` | Generar enlaces Falcon incorrectos o fallar conexión regional. |
| `FALCON_ARTIFACT_MODE` | Conservar o eliminar artefactos sensibles de forma no esperada. |
| `FALCON_OUTPUT_DIR` | Guardar artefactos o Excel en una ubicación no esperada. |

---

## Recomendación por cliente

Usa una sesión nueva de PowerShell para cada cliente.

Flujo recomendado:

1. Abrir nueva terminal.
2. Activar `.venv`.
3. Exportar variables del cliente.
4. Validar variables visualmente.
5. Ejecutar `python main.py`.
6. Revisar salida de consola.
7. Validar Excel generado.
8. Cerrar terminal.

---

## Limpieza de variables

Si necesitas reutilizar la misma consola, limpia variables antes de cambiar de cliente:

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
Remove-Item Env:FALCON_ARTIFACT_MODE -ErrorAction SilentlyContinue
```

Luego exporta solo las variables del nuevo cliente.

---

## Modo de artefactos recomendado

Para operación normal con clientes:

```powershell
$env:FALCON_ARTIFACT_MODE="final_only"
```

Este modo intenta eliminar artefactos intermedios después de generar el Excel final.

Importante:

- la limpieza puede fallar si Windows, OneDrive, antivirus o permisos bloquean archivos;
- si falla, la carpeta de artefactos puede conservarse;
- revisa la consola después de ejecutar;
- elimina manualmente artefactos sensibles si se conservaron por bloqueo del sistema.

---

## Cuándo usar `standard`

Usa `standard` cuando necesites revisión técnica interna, pero no quieras conservar payload raw completo.

```powershell
$env:FALCON_ARTIFACT_MODE="standard"
```

Este modo puede ser útil para:

- revisar CSV técnicos;
- validar conteos;
- compartir evidencia interna limitada;
- investigar resultados sin conservar JSON raw.

---

## Cuándo usar `debug`

Usa `debug` solo para desarrollo o troubleshooting.

```powershell
$env:FALCON_ARTIFACT_MODE="debug"
```

Este modo conserva todos los artefactos, incluyendo información raw que puede ser sensible.

Usos válidos:

- crear soporte para nuevos `risk_type`;
- depurar parsers;
- analizar cambios de estructura en payloads GraphQL;
- investigar errores de parsing.

No recomendado para corridas operativas normales.

---

## Ubicación del Excel final

El Excel final se genera en el directorio padre de `FALCON_OUTPUT_DIR`.

Con valor por defecto:

```powershell
$env:FALCON_OUTPUT_DIR="output"
```

el Excel queda en la raíz del repositorio.

Si se configura una ruta personalizada:

```powershell
$env:FALCON_OUTPUT_DIR="C:\Temp\identity_output"
```

el Excel quedará en:

```text
C:\Temp\
```

Esto debe tomarse en cuenta para evitar buscar el Excel en la ubicación equivocada.

---

## Checklist antes de ejecutar

- [ ] Estoy en el repositorio correcto.
- [ ] La `.venv` está activa.
- [ ] `FALCON_CLIENT_ID` corresponde al tenant correcto.
- [ ] `FALCON_TARGET_DOMAIN` corresponde al cliente correcto.
- [ ] `FALCON_DELIVERABLE_NAME` está correcto.
- [ ] `FALCON_BASE_URL` corresponde a la región correcta.
- [ ] `FALCON_ARTIFACT_MODE` está definido según el objetivo.
- [ ] No hay variables heredadas de otro cliente.
- [ ] Sé dónde quedará el Excel final.

---

## Checklist después de ejecutar

- [ ] El Excel se generó correctamente.
- [ ] El nombre del Excel corresponde al cliente.
- [ ] La fecha del archivo corresponde a la corrida actual.
- [ ] La consola no mostró errores críticos.
- [ ] No hay `Parser errors` sin revisar.
- [ ] No hay `Unclassified` sin revisar.
- [ ] Los enlaces Falcon abren en la región correcta.
- [ ] No quedaron artefactos raw sensibles si se usó `final_only`.
- [ ] El Excel fue revisado antes de compartirlo.

---

## Protección de información sensible

No subir al repositorio:

- credenciales;
- `.env` real;
- archivos Excel de clientes;
- JSON raw;
- CSV con evidencia sensible;
- contenido de `output/`;
- capturas con datos de tenant;
- errores de consola con identificadores sensibles.

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

## Buenas prácticas de entrega

Antes de enviar el Excel a cliente:

1. Revisar nombre del archivo.
2. Abrir el Excel y validar contenido.
3. Confirmar que no existan hojas internas no deseadas visibles.
4. Confirmar que los enlaces Falcon son correctos.
5. Revisar P1 y riesgos críticos.
6. Confirmar si existen hallazgos que requieren L2 antes de presentar.
7. Evitar adjuntar artefactos técnicos salvo que estén aprobados.
8. Redactar el correo como reporte de hallazgos, no como incidente confirmado, salvo que haya investigación que lo respalde.
