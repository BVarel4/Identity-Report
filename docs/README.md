# Documentación del proyecto

Esta carpeta contiene documentación complementaria para analistas, operadores MSSP y responsables técnicos que necesiten entender, operar o extender el uso del reporte de CrowdStrike Identity Protection.

El `README.md` principal del repositorio se mantiene enfocado en instalación, configuración y ejecución. Esta carpeta concentra el conocimiento extendido para que el repositorio sea más fácil de usar para distintos perfiles.

## Contenido

| Documento | Objetivo |
| --- | --- |
| [Base de conocimiento para revisión L1](l1-knowledge-base.md) | Guía operativa para analistas L1: cómo revisar el Excel, validar hallazgos, crear tickets y escalar. |
| [Referencias técnicas de identidad](identity-references.md) | Base de aprendizaje sobre identidad, Active Directory, Kerberos, NTLM, LDAP, AD CS, MITRE, NIST y CrowdStrike. |
| [Operación en entorno MSSP](mssp-operations.md) | Buenas prácticas para ejecutar el proyecto con múltiples clientes, proteger artefactos y evitar mezcla de tenants. |
| [Dominios de atención](risk-domains.md) | Explicación de los dominios usados por el reporte, cómo interpretarlos y cuándo escalar. |

## Uso recomendado

- Si solo necesitas ejecutar el proyecto, usa el `README.md` principal.
- Si eres analista L1, empieza por `l1-knowledge-base.md`.
- Si necesitas entender el contexto técnico de los riesgos, consulta `identity-references.md` y `risk-domains.md`.
- Si operas varios clientes, revisa `mssp-operations.md` antes de ejecutar el reporte.
