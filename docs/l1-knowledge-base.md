# Base de conocimiento para revisión L1

Esta guía está pensada para analistas L1 de SOC o MSSP que reciben el reporte generado desde CrowdStrike Identity Protection y necesitan convertirlo en acciones operativas: validar hallazgos, priorizar, documentar evidencia, crear tickets y escalar correctamente.

El objetivo del L1 no es cerrar remediaciones sensibles por cuenta propia. Su función principal es ordenar hallazgos, validar lo básico, documentar evidencia, identificar riesgos que requieren L2 o equipo de identidad y evitar que se presenten conclusiones no verificadas al cliente.

---

## Principios de trabajo para L1

1. **No asumir que un hallazgo es incidente confirmado.** Un riesgo de Identity Protection indica exposición, anomalía, mala configuración o posible actividad adversaria, pero debe validarse en Falcon y con el contexto del cliente.
2. **No remediar sin owner.** Cambios sobre cuentas, privilegios, políticas de AD, Kerberos, AD CS o controladores de dominio requieren validación del responsable técnico.
3. **Priorizar por impacto, no solo por volumen.** Un único hallazgo sobre una cuenta privilegiada puede ser más importante que muchos hallazgos de higiene en cuentas estándar.
4. **Escalar cuando haya privilegio, movimiento lateral o ataque activo.** Estos escenarios pueden tener impacto operativo o de seguridad alto.
5. **Usar el reporte como punto de partida.** La fuente primaria sigue siendo CrowdStrike Falcon y el contexto del tenant.

---

## Qué revisar antes de compartir el reporte

No compartas el reporte como entregable final si ocurre cualquiera de estos casos:

- El Excel no se generó correctamente.
- El nombre del archivo no corresponde al cliente.
- `FALCON_TARGET_DOMAIN` no corresponde al dominio del cliente actual.
- `FALCON_DELIVERABLE_NAME` no corresponde al cliente o entregable actual.
- La consola mostró `Parser errors` o `Structure issues` mayores que cero.
- Aparecen riesgos `Unclassified` sin revisión L2.
- Los enlaces Falcon apuntan a una región inesperada.
- Hay dudas sobre si la corrida apunta al tenant correcto.
- Se ejecutó con `FALCON_ARTIFACT_MODE="debug"` y quedaron artefactos raw sensibles sin control.

Si aparece `Requires review`, no cierres esos hallazgos como conclusión final. Pueden usarse para revisión interna, pero deben validarse por L2 o por el equipo de identidad antes de presentarse como remediación definitiva.

---

## Flujo recomendado de revisión

### 1. Confirmar archivo y cliente

Abre el Excel generado y valida:

- nombre del archivo;
- dominio mostrado;
- cliente o entregable esperado;
- fecha de generación;
- región Falcon de los enlaces.

Si alguno de estos datos no coincide, detén la revisión y confirma la configuración usada.

### 2. Revisar salud de la corrida

Revisa la salida de consola y, si el modo de artefactos lo permite, los CSV de auditoría.

Busca:

- `Parser errors`;
- `Structure issues`;
- `Unknown risk types`;
- `Unclassified`;
- `Requires review`.

Si hay errores de parser o estructura, no asumas que el reporte está completo. Escala para revisión.

### 3. Leer el Resumen Ejecutivo

Usa `Resumen Ejecutivo` para entender:

- volumen total de hallazgos;
- dominios de atención dominantes;
- riesgos de mayor concentración;
- presencia de entidades críticas;
- posibles rutas de ataque.

Esta hoja sirve para contexto, no para trabajar cada caso individual.

### 4. Trabajar desde Plan de Atención

La hoja principal para operación es `Plan de Atencion`.

Orden sugerido:

1. Filtrar `Prioridad de revision = P1`.
2. Filtrar `Estado sugerido = Atencion inmediata`.
3. Revisar entidades privilegiadas, de servicio, administrativas o críticas.
4. Abrir el `Enlace Falcon` para validar contexto.
5. Crear ticket o escalar según el riesgo.

### 5. Revisar Riesgos Prioritarios

Usa esta hoja para identificar si el problema es:

- masivo;
- concentrado en pocas entidades;
- asociado a un dominio específico;
- relacionado con postura, privilegios, Kerberos, endpoints o actividad adversaria.

No cierres hallazgos solo por volumen. Un riesgo de bajo volumen puede tener alta criticidad si afecta cuentas privilegiadas.

### 6. Revisar Entidades Críticas

Esta hoja ayuda a identificar cuentas o endpoints con múltiples riesgos correlacionados.

Escala si una entidad:

- tiene varios riesgos de dominios distintos;
- es privilegiada;
- aparece en rutas de ataque;
- es cuenta de servicio;
- tiene acceso a servidores críticos;
- está asociada a endpoints no gestionados o compartidos.

### 7. Revisar Rutas de Ataque

Si existe la hoja `Rutas de Ataque`, debe tratarse con prioridad alta.

Una ruta de ataque puede indicar una combinación de condiciones que permitirían llegar a una cuenta, sistema o recurso sensible. CrowdStrike destaca la importancia de identificar y neutralizar rutas de ataque antes de que sean utilizadas por adversarios.

Escala cualquier ruta de ataque hacia L2 o equipo de identidad, especialmente si involucra:

- cuentas privilegiadas;
- AD CS;
- Kerberos;
- endpoints no gestionados;
- privilegios locales;
- controladores de dominio;
- servidores críticos.

### 8. Usar Detalle Operativo

`Detalle Operativo` sirve para documentar evidencia y preparar tickets.

Campos útiles:

- entidad;
- riesgo;
- dominio de atención;
- prioridad;
- accionabilidad;
- impacto probable;
- evidencia disponible;
- acción recomendada;
- enlace Falcon.

---

## Cómo leer prioridad y accionabilidad

### Prioridad de revisión

| Prioridad | Interpretación | Acción L1 |
| --- | --- | --- |
| `P1` | Riesgo de atención inmediata. Puede involucrar privilegios, movimiento lateral, exposición crítica o actividad adversaria. | Validar en Falcon, crear ticket y escalar si toca sistemas sensibles. |
| `P2` | Riesgo importante que requiere análisis y plan de remediación. | Validar contexto, documentar evidencia y coordinar revisión. |
| `P3` | Mejora operativa o higiene. | Agrupar con hallazgos similares y proponer remediación planificada. |

### Accionabilidad

| Valor | Interpretación | Acción L1 |
| --- | --- | --- |
| `Accion directa` | El hallazgo normalmente permite una remediación concreta. | Documentar y coordinar owner, ventana e impacto antes de ejecutar. |
| `Validacion en Falcon` | Requiere confirmar entidad, contraparte, fecha, origen o contexto adicional. | Abrir Falcon y documentar hallazgos visibles. |
| `Investigacion guiada` | No debe cerrarse en L1. Requiere análisis más profundo. | Escalar a L2, SOC o equipo de identidad. |

---

## Cuándo escalar a L2

Escala siempre si el hallazgo involucra:

- cuentas privilegiadas;
- cuentas de servicio;
- controladores de dominio;
- AD CS o plantillas de certificados;
- KRBTGT;
- Kerberos avanzado;
- Pass-the-Hash;
- Pass-the-Ticket;
- rutas de ataque;
- movimiento lateral;
- endpoints no gestionados usados por usuarios privilegiados;
- actividad que parezca reconocimiento, fuerza bruta, abuso de credenciales o comportamiento adversario;
- dudas sobre el impacto de remediar.

También escala si:

- el enlace Falcon no abre;
- el enlace apunta a una región inesperada;
- la evidencia del Excel no coincide con lo visible en Falcon;
- el cliente pregunta si es incidente confirmado;
- el cliente solicita remediación inmediata sobre cuentas críticas;
- el hallazgo requiere cambio en GPO, política de AD, LDAP, SMB, Kerberos o certificados.

---

## Criterios de validación en Falcon

Para cada hallazgo priorizado, valida en Falcon:

1. entidad afectada;
2. tipo de riesgo;
3. severidad de entidad;
4. fecha y contexto visible;
5. recomendaciones o descripción del riesgo;
6. relación con otras entidades;
7. si existe ruta de ataque;
8. si hay detecciones, incidentes o actividad relacionada;
9. si la entidad es privilegiada o sensible;
10. si el hallazgo coincide con el alcance acordado con el cliente.

Si Falcon muestra más contexto que el Excel, usa Falcon como fuente primaria para la investigación.

---

## Plantilla corta para ticket MSSP

```text
Titulo:
[Identity Protection] <Riesgo> en <Entidad> - <Prioridad>

Resumen:
Se identificó <Riesgo> sobre <Entidad> dentro del reporte de CrowdStrike Identity Protection. Dominio de atención: <Dominio de atención>.

Impacto probable:
<Impacto probable del Excel>

Evidencia:
<Evidencia disponible del Excel>
Enlace Falcon: <Enlace Falcon>

Acción recomendada:
<Acción recomendada del Excel>

Validación L1:
- Cliente/dominio confirmado: Sí/No
- Entidad revisada en Falcon: Sí/No
- Riesgo visible en Falcon: Sí/No
- Requiere L2: Sí/No
- Motivo de escalamiento: <motivo si aplica>

Notas:
<Observaciones relevantes, owner pendiente, dudas o validaciones requeridas>
```

---

## Plantilla corta para comentario al cliente

```text
Durante la revisión de Identity Protection se identificaron hallazgos priorizados por impacto operativo, criticidad y concentración.

Se recomienda iniciar por los elementos P1 del Plan de Atención, validar owner y uso legítimo de las entidades afectadas, y coordinar ventanas de remediación para las acciones que impliquen cambios sobre cuentas, privilegios, autenticación, configuración de directorio o endpoints críticos.

Los hallazgos marcados como investigación o validación requieren confirmación adicional en Falcon antes de considerarse cerrados.
```

---

## Errores comunes en revisión L1

Evita estos errores:

- Tratar todos los hallazgos como incidentes confirmados.
- Remediar cuentas privilegiadas sin validar owner.
- Enfocarse solo en cantidad y no en criticidad.
- Ignorar rutas de ataque por tener pocos registros.
- Cerrar riesgos `Unclassified` sin revisión.
- Compartir artefactos raw con cliente.
- No revisar si el Excel corresponde al tenant correcto.
- Copiar recomendaciones sin validar impacto operativo.
- Confundir severidad de entidad con severidad independiente por `riskFactor`.

---

## Relación con CrowdStrike Identity Protection

CrowdStrike Identity Protection está enfocado en reducir el riesgo de identidad, detectar amenazas relacionadas con credenciales, correlacionar identidad con endpoint y ayudar a detener movimiento lateral. El reporte generado por este proyecto debe entenderse como una capa de análisis y presentación sobre los hallazgos que devuelve CrowdStrike.

La revisión L1 debe apoyarse en:

- el Excel generado;
- los enlaces directos a Falcon;
- la descripción y recomendación visible en Falcon;
- el contexto del cliente;
- las guías internas de operación;
- las referencias técnicas de esta carpeta `docs/`.

---

## Checklist final para L1

Antes de pasar el caso a cliente o L2, confirma:

- [ ] El archivo corresponde al cliente correcto.
- [ ] El dominio consultado es correcto.
- [ ] La región Falcon es correcta.
- [ ] No hay errores de parser sin revisar.
- [ ] No hay riesgos `Unclassified` sin escalar.
- [ ] Los P1 fueron revisados primero.
- [ ] Las entidades privilegiadas fueron identificadas.
- [ ] Las rutas de ataque fueron escaladas.
- [ ] La evidencia fue copiada al ticket.
- [ ] No se compartieron artefactos raw sensibles.
- [ ] Las acciones recomendadas fueron redactadas como recomendaciones, no como cambios ejecutados.
