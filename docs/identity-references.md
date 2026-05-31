# Referencias técnicas de identidad

Esta guía reúne referencias y conceptos técnicos para analistas que revisan hallazgos de CrowdStrike Identity Protection. Su objetivo es servir como base de aprendizaje para comprender riesgos de identidad, autenticación, privilegios y movimiento lateral.

No reemplaza la documentación oficial de CrowdStrike ni el análisis dentro de Falcon. Debe usarse como apoyo para interpretar mejor los hallazgos del reporte.

---

## CrowdStrike Identity Protection

CrowdStrike Falcon Identity Protection se enfoca en proteger identidades híbridas, correlacionar identidad con endpoint, detectar amenazas basadas en identidad y ayudar a reducir rutas de ataque y movimiento lateral.

Referencias:

- CrowdStrike Falcon Identity Protection: https://www.crowdstrike.com/en-us/platform/next-gen-identity-security/identity-protection/
- CrowdStrike Identity Threat Detection and Response: https://www.crowdstrike.com/en-us/platform/next-gen-identity-security/itdr/
- CrowdStrike Next-Gen Identity Security: https://www.crowdstrike.com/en-us/platform/next-gen-identity-security/
- CrowdStrike Attack Path Analysis: https://www.crowdstrike.com/en-us/platform/exposure-management/attack-path-analysis/

Uso sugerido:

- entender el foco de Identity Protection;
- contextualizar riesgos de identidad y rutas de ataque;
- explicar por qué identidad, endpoint y movimiento lateral deben analizarse en conjunto;
- fundamentar priorización basada en exposición y no solo en volumen.

---

## FalconPy e Identity Protection GraphQL

Este proyecto usa FalconPy para consultar CrowdStrike Identity Protection por GraphQL.

Referencias:

- FalconPy SDK: https://github.com/CrowdStrike/falconpy
- FalconPy Documentation: https://www.falconpy.io/
- FalconPy Identity Protection: https://www.falconpy.io/Service-Collections/Identity-Protection.html
- CrowdStrike Developer Center: https://developer.crowdstrike.com/
- CrowdStrike OpenAPI Docs: https://developer.crowdstrike.com/docs/openapi/

Punto importante:

Aunque el proyecto realiza consultas de lectura, el endpoint GraphQL de Identity Protection requiere el scope:

```text
identity-protection-graphql:write
```

En la consola de CrowdStrike esto normalmente se refleja como:

```text
Identity Protection GraphQL = Write
```

---

## Fundamentos de identidad y autenticación

Antes de interpretar riesgos específicos, conviene entender cómo funcionan autenticación, directorio, credenciales y protocolos en ambientes Windows/Active Directory.

Referencias principales:

- Windows Authentication Overview: https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/windows-authentication-overview
- Kerberos Authentication Overview: https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview
- NTLM Overview: https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview
- NIST SP 800-63-4 Digital Identity Guidelines: https://www.nist.gov/publications/nist-sp-800-63-4-digital-identity-guidelines

Conceptos clave:

- identidad no es solo usuario; también incluye cuentas de servicio, equipos, identidades privilegiadas, identidades no humanas y relaciones de acceso;
- Kerberos es el protocolo moderno principal en dominios Windows;
- NTLM sigue existiendo por compatibilidad y puede aumentar superficie de ataque;
- una mala higiene de credenciales puede facilitar abuso, movimiento lateral y escalamiento;
- MFA resistente a phishing y gobierno de identidad reducen riesgo, pero no eliminan la necesidad de monitoreo.

---

## Password Hygiene e Identity Hygiene

Dominios relacionados:

- `Password Hygiene`
- `Identity Hygiene`

Riesgos típicos:

- contraseñas débiles;
- contraseñas reutilizadas;
- políticas de contraseña insuficientes;
- rotación deficiente;
- cuentas compartidas;
- baja trazabilidad.

Referencias:

- Microsoft Entra Password Protection: https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad
- Microsoft Entra Password Protection for AD DS: https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad-on-premises
- MITRE ATT&CK Password Spraying T1110.003: https://attack.mitre.org/techniques/T1110/003/
- MITRE ATT&CK Credential Stuffing T1110.004: https://attack.mitre.org/techniques/T1110/004/

Qué debe entender L1:

- una contraseña débil o reutilizada no siempre significa compromiso, pero sí aumenta probabilidad de abuso;
- cuentas compartidas reducen trazabilidad y complican atribución;
- si una cuenta privilegiada aparece con problemas de contraseña, la prioridad sube;
- password spraying y credential stuffing son técnicas comunes contra identidades.

---

## Account Lifecycle y Access Change

Dominios relacionados:

- `Account Lifecycle`
- `Access Change`

Riesgos típicos:

- cuentas inactivas;
- cuentas obsoletas;
- uso de cuentas stale;
- accesos nuevos a servidores;
- cambios de privilegio o alcance.

Referencias:

- Microsoft Entra ID Governance overview: https://learn.microsoft.com/en-us/entra/id-governance/identity-governance-overview
- Lifecycle Workflows: https://learn.microsoft.com/en-us/entra/id-governance/what-are-lifecycle-workflows
- Access Reviews: https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview

Qué debe entender L1:

- cuentas inactivas pueden convertirse en puntos de entrada si no se deshabilitan o revisan;
- accesos nuevos deben validarse con owner y justificación;
- procesos Joiner/Mover/Leaver deficientes generan acumulación de riesgo;
- no se debe deshabilitar una cuenta de servicio sin confirmar impacto.

---

## Endpoint Exposure, Hardening y Posture

Dominios relacionados:

- `Endpoint Exposure`
- `Endpoint Hardening`
- `Endpoint Posture`

Riesgos típicos:

- endpoints compartidos;
- endpoints no gestionados;
- endpoints stale;
- uso de endpoints vulnerables por usuarios privilegiados;
- SMB signing deshabilitado;
- postura deficiente del activo.

Referencias:

- SMB signing overview: https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview
- Windows Authentication Overview: https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/windows-authentication-overview
- CrowdStrike ITDR: https://www.crowdstrike.com/en-us/platform/next-gen-identity-security/itdr/

Qué debe entender L1:

- un usuario privilegiado usando un endpoint no gestionado aumenta el riesgo;
- endpoints compartidos reducen trazabilidad;
- configuraciones débiles como falta de SMB signing pueden habilitar ataques de relay o abuso de autenticación;
- validar siempre si el endpoint es servidor, estación crítica, equipo administrativo o activo sin owner.

---

## Directory Hardening y LDAP

Dominios relacionados:

- `Directory Hardening`

Riesgos típicos:

- LDAP signing deshabilitado;
- LDAPS channel binding débil;
- configuración insegura de directorio;
- exposición a relay o manipulación de tráfico.

Referencias:

- LDAP signing for Active Directory Domain Services: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing
- How to enable LDAP signing in Windows Server: https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server
- Domain controller LDAP server channel binding token requirements: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/domain-controller-ldap-server-channel-binding-token-requirements

Qué debe entender L1:

- LDAP signing ayuda a proteger integridad del tráfico LDAP;
- cambios de LDAP/LDAPS pueden afectar aplicaciones heredadas;
- cualquier ajuste en controladores de dominio requiere coordinación con AD/infraestructura;
- estos hallazgos normalmente deben escalarse a L2 o al equipo de directorio.

---

## Kerberos Exposure

Dominios relacionados:

- `Kerberos Exposure`
- `Credential Abuse`
- `Lateral Movement`

Riesgos típicos:

- cuentas con SPN;
- contraseña antigua de KRBTGT;
- exposición a Kerberoasting;
- abuso de tickets;
- rutas hacia cuentas privilegiadas.

Referencias:

- Kerberos Authentication Overview: https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview
- MITRE ATT&CK Steal or Forge Kerberos Tickets T1558: https://attack.mitre.org/techniques/T1558/
- MITRE ATT&CK Kerberoasting T1558.003: https://attack.mitre.org/techniques/T1558/003/
- CrowdStrike Golden Ticket Attack: https://www.crowdstrike.com/en-us/cybersecurity-101/cyberattacks/golden-ticket-attack/

Qué debe entender L1:

- Kerberos es crítico en Active Directory;
- KRBTGT es altamente sensible;
- cuentas con SPN pueden ser objetivo de Kerberoasting;
- rotaciones de KRBTGT o cambios Kerberos deben tratarse con mucha cautela;
- cualquier hallazgo Kerberos sensible debe escalarse.

---

## Credential Abuse

Dominios relacionados:

- `Credential Abuse`
- `Threat Activity`
- `Lateral Movement`

Riesgos típicos:

- Pass-the-Hash;
- Pass-the-Ticket;
- robo de credenciales;
- fuerza bruta;
- password spraying;
- uso anómalo de credenciales.

Referencias:

- MITRE ATT&CK OS Credential Dumping T1003: https://attack.mitre.org/techniques/T1003/
- MITRE ATT&CK Pass the Hash T1550.002: https://attack.mitre.org/techniques/T1550/002/
- MITRE ATT&CK Pass the Ticket T1550.003: https://attack.mitre.org/techniques/T1550/003/
- MITRE ATT&CK Credential Access TA0006: https://attack.mitre.org/tactics/TA0006/

Qué debe entender L1:

- abuso de credenciales puede indicar actividad adversaria real;
- no se debe cerrar como higiene sin revisar contexto;
- validar origen, destino, cuenta, endpoint y frecuencia;
- escalar si hay cuentas privilegiadas, servidores críticos o movimiento lateral.

---

## Privilege Exposure

Dominios relacionados:

- `Privilege Exposure`

Riesgos típicos:

- privilegios discretos o poco visibles;
- cuentas privilegiadas expuestas;
- endpoint no gestionado usado por usuario privilegiado;
- equipos privilegiados;
- sesiones privilegiadas en equipos compartidos.

Referencias:

- Attractive Accounts for Credential Theft: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/attractive-accounts-for-credential-theft
- Microsoft Phishing-resistant MFA: https://learn.microsoft.com/en-us/security/zero-trust/sfi/phishing-resistant-mfa
- MITRE ATT&CK Privilege Escalation TA0004: https://attack.mitre.org/tactics/TA0004/

Qué debe entender L1:

- los privilegios aumentan impacto, incluso si el volumen del hallazgo es bajo;
- cuentas privilegiadas requieren validación de owner y justificación;
- endpoints no gestionados o compartidos elevan riesgo cuando interactúan con privilegios;
- privilegios sobre AD, servidores críticos o endpoints administrativos deben escalarse.

---

## Certificate Exposure y AD CS

Dominios relacionados:

- `Certificate Exposure`
- `Privilege Exposure`
- `Lateral Movement`

Riesgos típicos:

- plantillas de certificado que permiten autenticación indebida;
- AD CS mal configurado;
- enrollment riesgoso;
- posibilidad de autenticarse como otros usuarios;
- escalamiento por certificados.

Referencias:

- Active Directory Certificate Services Overview: https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview
- SpecterOps Certified Pre-Owned: https://specterops.io/blog/2021/06/17/certified-pre-owned/

Qué debe entender L1:

- AD CS puede convertirse en una vía crítica de escalamiento;
- cambios en plantillas de certificados pueden tener impacto amplio;
- cualquier hallazgo de AD CS debe escalarse;
- no se debe recomendar cambio directo sin análisis de L2 o equipo de AD.

---

## Lateral Movement y Attack Paths

Dominios relacionados:

- `Lateral Movement`
- `Threat Activity`
- `Privilege Exposure`
- `Credential Abuse`

Riesgos típicos:

- rutas de ataque hacia cuentas privilegiadas;
- movimiento lateral por credenciales;
- uso de tickets, hashes o sesiones;
- acceso encadenado entre entidades;
- exposición indirecta por relaciones de identidad y endpoint.

Referencias:

- MITRE ATT&CK Lateral Movement TA0008: https://attack.mitre.org/tactics/TA0008/
- MITRE ATT&CK Use Alternate Authentication Material T1550: https://attack.mitre.org/techniques/T1550/
- CrowdStrike Attack Path Analysis: https://www.crowdstrike.com/en-us/platform/exposure-management/attack-path-analysis/

Qué debe entender L1:

- una ruta de ataque es más importante que un hallazgo aislado;
- puede representar cómo un adversario podría llegar a un objetivo sensible;
- si involucra privilegios, Kerberos, AD CS o endpoints críticos, debe escalarse;
- el objetivo no es solo corregir un punto, sino cortar la ruta completa.

---

## Threat Activity

Dominios relacionados:

- `Threat Activity`
- `Behavioral Anomaly`
- `Credential Abuse`

Riesgos típicos:

- reconocimiento LDAP;
- RPC anómalo;
- credential scanning;
- password brute force;
- actividad fuera de línea base;
- comportamiento que puede sugerir adversario.

Referencias:

- MITRE ATT&CK Enterprise Tactics: https://attack.mitre.org/tactics/enterprise/
- MITRE ATT&CK Credential Access TA0006: https://attack.mitre.org/tactics/TA0006/
- MITRE ATT&CK Discovery TA0007: https://attack.mitre.org/tactics/TA0007/
- MITRE ATT&CK Lateral Movement TA0008: https://attack.mitre.org/tactics/TA0008/

Qué debe entender L1:

- actividad adversaria no debe tratarse como simple higiene;
- validar tiempos, origen, destino y entidad;
- buscar correlación con detecciones o incidentes;
- escalar si hay señales repetidas, cuentas privilegiadas o actividad hacia activos críticos.

---

## Ruta de aprendizaje recomendada

Para analistas que están empezando en identidad:

1. Leer Windows Authentication Overview.
2. Entender Kerberos y NTLM.
3. Revisar conceptos de LDAP, SMB signing y AD CS.
4. Leer NIST SP 800-63-4 para fundamentos de identidad digital.
5. Revisar MITRE Credential Access y Lateral Movement.
6. Revisar la documentación de CrowdStrike Identity Protection.
7. Practicar leyendo el Excel generado y abriendo los enlaces Falcon.
8. Comparar hallazgos del reporte con la explicación visible en Falcon.
9. Escalar dudas antes de recomendar cambios sensibles.

---

## Cómo usar estas referencias en un reporte o ticket

Una forma práctica:

1. Identificar el dominio de atención.
2. Confirmar si el hallazgo es higiene, postura, privilegio, autenticación o actividad adversaria.
3. Abrir la referencia funcional correspondiente.
4. Usar MITRE si el hallazgo puede formar parte de una técnica adversaria.
5. Usar Microsoft/NIST si el hallazgo requiere justificar control, política o gobierno de identidad.
6. Usar CrowdStrike/Falcon como fuente primaria para el hallazgo concreto.
7. Redactar impacto, evidencia y recomendación en lenguaje operativo.
