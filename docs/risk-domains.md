# Dominios de atención y criterios de interpretación

Los dominios de atención son una agrupación operativa local usada por el proyecto para convertir `risk_type` de CrowdStrike Identity Protection en frentes claros de análisis, priorización y remediación.

No son una taxonomía oficial cerrada de CrowdStrike, MITRE, NIST o Microsoft. La fuente primaria del hallazgo sigue siendo CrowdStrike Falcon Identity Protection.

---

## Cómo interpretar los dominios

Un dominio de atención ayuda a responder:

- ¿Qué tipo de problema representa el hallazgo?
- ¿Qué equipo debería revisarlo?
- ¿Qué tan sensible puede ser la remediación?
- ¿Debe escalarse a L2?
- ¿Qué referencia técnica puede ayudar a entenderlo?

No debe usarse como veredicto absoluto. El analista debe confirmar el hallazgo en Falcon y considerar el contexto del cliente.

---

## Mapa rápido por dominio

| Dominio | Qué significa | Revisar primero | Escalar si |
| --- | --- | --- | --- |
| `Password Hygiene` | Debilidades de contraseña, rotación, reutilización o política. | Cuenta afectada, privilegio, política vigente. | Afecta cuenta privilegiada, servicio o muchas cuentas. |
| `Identity Hygiene` | Cuentas compartidas o baja trazabilidad. | Owner, uso legítimo, usuarios asociados. | Cuenta compartida accede a sistemas críticos. |
| `Account Lifecycle` | Cuentas inactivas, stale o con ciclo de vida deficiente. | Último uso, owner, criticidad. | Cuenta es privilegiada, de servicio o productiva. |
| `Access Change` | Accesos nuevos o cambios que requieren validación. | Fecha, recurso, justificación. | Acceso a servidor crítico o fuera de horario. |
| `Behavioral Anomaly` | Comportamiento fuera de línea base. | Origen, destino, frecuencia, usuario. | Actividad repetida o asociada a privilegios. |
| `Identity Correlation` | Riesgo derivado de relaciones entre identidades. | Entidades relacionadas y contexto. | Relación permite acceso sensible. |
| `Endpoint Exposure` | Riesgo indirecto por endpoint compartido, stale o riesgoso. | Equipo, usuario, gestión del endpoint. | Lo usa una cuenta privilegiada. |
| `Endpoint Hardening` | Configuración débil en endpoint o protocolo. | Protocolo, sistema afectado, compatibilidad. | Afecta servidores o requiere cambio de GPO. |
| `Endpoint Posture` | Activo vulnerable o desactualizado. | Criticidad, exposición, owner. | Es servidor crítico o no tiene owner. |
| `Directory Hardening` | Debilidades de directorio, LDAP o autenticación. | DCs, políticas, compatibilidad. | Involucra controladores de dominio. |
| `Credential Abuse` | Posible abuso o reutilización de credenciales. | Cuenta, origen, destino, técnica. | Hay Pass-the-Hash, Pass-the-Ticket o privilegios. |
| `Kerberos Exposure` | Riesgo relacionado con Kerberos, SPN o KRBTGT. | Cuenta, SPN, criticidad, antigüedad. | Involucra KRBTGT, SPN sensible o tickets. |
| `Certificate Exposure` | Riesgo por AD CS o plantillas de certificados. | Plantilla, enrollment, autenticación. | Puede permitir autenticación como otro usuario. |
| `Privilege Exposure` | Exposición de privilegios o cuentas de alto impacto. | Tipo de privilegio, entidad, endpoint. | Cualquier privilegio administrativo sensible. |
| `Lateral Movement` | Condiciones que facilitan movimiento lateral. | Ruta, origen, destino, credenciales. | Existe attack path o activo crítico. |
| `Threat Activity` | Señales de actividad adversaria o investigación activa. | Técnica, frecuencia, entidades. | Hay actividad repetida o posible incidente. |
| `Unclassified` | Riesgo no catalogado localmente. | Payload y Falcon. | Siempre escalar antes de entregar conclusión. |

---

## Password Hygiene

### Interpretación

Riesgos relacionados con calidad, rotación o reutilización de contraseñas.

### Preguntas para L1

- ¿La cuenta es privilegiada?
- ¿La cuenta es de servicio?
- ¿La debilidad afecta muchas cuentas?
- ¿Existe política de contraseña documentada?
- ¿Se observa uso reciente de la cuenta?

### Acción sugerida

- Validar en Falcon.
- Documentar impacto.
- Recomendar revisión de política, rotación o controles de contraseña.
- Escalar si afecta privilegios o cuentas de servicio.

---

## Identity Hygiene

### Interpretación

Riesgos que reducen trazabilidad, como cuentas compartidas o identidades con uso ambiguo.

### Preguntas para L1

- ¿Quién es el owner?
- ¿La cuenta es usada por varias personas?
- ¿Tiene privilegios?
- ¿Se usa para tareas administrativas?

### Acción sugerida

- Solicitar owner y justificación.
- Recomendar cuentas nominativas cuando aplique.
- Escalar si tiene privilegios o acceso a sistemas críticos.

---

## Account Lifecycle

### Interpretación

Riesgos por cuentas stale, inactivas o con ciclo de vida deficiente.

### Preguntas para L1

- ¿Cuándo fue el último uso?
- ¿La cuenta sigue siendo necesaria?
- ¿Es cuenta humana o de servicio?
- ¿Tiene privilegios o acceso sensible?

### Acción sugerida

- Validar owner.
- Recomendar revisión Joiner/Mover/Leaver.
- No deshabilitar sin validar impacto.

---

## Access Change

### Interpretación

Accesos nuevos o cambios que pueden requerir confirmación.

### Preguntas para L1

- ¿Qué acceso cambió?
- ¿A qué recurso se accedió?
- ¿El horario es esperado?
- ¿El owner lo reconoce?

### Acción sugerida

- Validar en Falcon.
- Confirmar con owner.
- Escalar si involucra sistemas críticos.

---

## Behavioral Anomaly

### Interpretación

Actividad fuera del comportamiento esperado o línea base.

### Preguntas para L1

- ¿La anomalía es puntual o repetida?
- ¿Cuál es el origen?
- ¿Cuál es el destino?
- ¿Afecta cuenta privilegiada?

### Acción sugerida

- Revisar actividad relacionada.
- Buscar detecciones o incidentes asociados.
- Escalar si hay patrón repetido o actividad sensible.

---

## Directory Hardening

### Interpretación

Debilidades en configuración de directorio, autenticación LDAP o integridad de tráfico.

### Preguntas para L1

- ¿Afecta controladores de dominio?
- ¿Implica LDAP signing o channel binding?
- ¿Puede afectar aplicaciones heredadas?
- ¿Requiere cambio de GPO?

### Acción sugerida

- Documentar hallazgo.
- Escalar a L2 o equipo de AD.
- No recomendar cambio inmediato sin validación de compatibilidad.

---

## Kerberos Exposure

### Interpretación

Riesgos relacionados con Kerberos, SPN, tickets o KRBTGT.

### Preguntas para L1

- ¿La cuenta tiene SPN?
- ¿Es cuenta privilegiada?
- ¿Involucra KRBTGT?
- ¿Puede relacionarse con Kerberoasting o tickets?

### Acción sugerida

- Validar en Falcon.
- Revisar criticidad.
- Escalar siempre si aparece KRBTGT o SPN sensible.

---

## Certificate Exposure

### Interpretación

Riesgos relacionados con AD CS, certificados o plantillas inseguras.

### Preguntas para L1

- ¿Qué plantilla está afectada?
- ¿Permite autenticación?
- ¿Permite enrollment amplio?
- ¿Puede permitir autenticarse como otro usuario?

### Acción sugerida

- Escalar a L2 o equipo de AD CS.
- No recomendar cambios directos sin revisión.
- Documentar evidencia y posible impacto.

---

## Privilege Exposure

### Interpretación

Exposición de cuentas, equipos o relaciones con alto nivel de privilegio.

### Preguntas para L1

- ¿Qué privilegio tiene la entidad?
- ¿Es privilegio directo o indirecto?
- ¿Se usa desde endpoint gestionado?
- ¿La cuenta tiene MFA o controles adicionales?

### Acción sugerida

- Priorizar alto.
- Validar owner.
- Escalar si hay privilegio administrativo o acceso sensible.

---

## Lateral Movement

### Interpretación

Riesgos que pueden facilitar desplazamiento entre sistemas o identidades.

### Preguntas para L1

- ¿Cuál es el origen y destino?
- ¿Qué credencial o relación habilita el movimiento?
- ¿Hay endpoint crítico involucrado?
- ¿Existe attack path?

### Acción sugerida

- Escalar a L2.
- Revisar rutas de ataque.
- Documentar entidades y relaciones.

---

## Threat Activity

### Interpretación

Señales de posible actividad adversaria o comportamiento que requiere investigación.

### Preguntas para L1

- ¿Hay detección relacionada?
- ¿La actividad se repite?
- ¿Afecta privilegios?
- ¿Hay reconocimiento, fuerza bruta o abuso de credenciales?

### Acción sugerida

- No tratar como simple higiene.
- Revisar Falcon e incidentes relacionados.
- Escalar si hay indicios de compromiso.

---

## Unclassified

### Interpretación

El proyecto recibió un `risk_type` que todavía no está mapeado localmente.

### Acción obligatoria

- Revisar payload raw si existe.
- Validar en Falcon.
- Documentar significado operativo.
- Escalar a L2.
- Agregar metadata a `risk_catalog.py` si aplica.
- Crear o ajustar parser si hay estructura útil.

No presentar un riesgo `Unclassified` como conclusión final sin revisión.
