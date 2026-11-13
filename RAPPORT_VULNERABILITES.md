# Rapport de vulnérabilités — `hr-management-api`

**Date :** 13/11/2026
**Périmètre :** `hr-management-api` (Express 4 + Prisma 5 + PostgreSQL + Redis/BullMQ), API REST `/api/v1` et workers.
**Méthode :** revue de code manuelle de `src/`, `prisma/` et de la configuration de déploiement ; instance lancée en local (PostgreSQL 15 + Redis 7, seed de 3 organisations) ; audit des dépendances (`pnpm audit`).
**Limite :** aucune exploitation n'a été rejouée contre l'instance. Les constats viennent de la lecture du code ; la plupart sont certains d'après la logique, mais ne sont pas prouvés dynamiquement.

## Note sur le format

Ce document reprend la structure des fiches du registre CVE / NVD. Chaque faille porte :

- un **identifiant interne** au format `HRAPI-2026-NNN` (il ne s'agit pas de CVE officiellement attribuées ; le préfixe `HRAPI` évite toute confusion avec une référence MITRE réelle) ;
- un **CWE** (Common Weakness Enumeration) ;
- un **score et un vecteur CVSS v3.1** ;
- le **composant affecté**, une **description**, un **impact** et une **remédiation**.

Les scores CVSS sont une évaluation de l'auteur de l'audit, non validée par un tiers.

## Grille de gravité CVSS v3.1

| Gravité | Score de base |
|---|---|
| Critique | 9.0 – 10.0 |
| Élevée | 7.0 – 8.9 |
| Moyenne | 4.0 – 6.9 |
| Faible | 0.1 – 3.9 |

## Tableau récapitulatif

| ID | Titre | CWE | CVSS | Gravité |
|---|---|---|---|---|
| HRAPI-2026-001 | Jeton de réinitialisation renvoyé dans la réponse HTTP | CWE-640 | 9.8 | Critique |
| HRAPI-2026-002 | Sélection du tenant via en-tête `X-Organization-Id` | CWE-639 | 9.1 | Critique |
| HRAPI-2026-003 | Élévation de privilèges vers `SUPER_ADMIN` | CWE-269 | 9.9 | Critique |
| HRAPI-2026-004 | IDOR généralisés / absence d'isolation multi-tenant | CWE-639 | 9.1 | Critique |
| HRAPI-2026-005 | Contrôle d'appartenance absent sur `organizations/:id` | CWE-639 | 9.1 | Critique |
| HRAPI-2026-006 | Téléchargement de documents sans autorisation | CWE-862 | 8.1 | Élevée |
| HRAPI-2026-007 | SSRF via `import-from-url` | CWE-918 | 9.1 | Critique |
| HRAPI-2026-026 | Écriture de fichiers arbitraires via `fileName` (path traversal) | CWE-22 | 9.1 | Critique |
| HRAPI-2026-008 | Sessions non révocables, refresh token rejouable | CWE-613 | 8.1 | Élevée |
| HRAPI-2026-009 | Rôle et organisation lus depuis le JWT | CWE-807 | 7.5 | Élevée |
| HRAPI-2026-010 | Secrets JWT par défaut codés en dur | CWE-798 | 9.8 | Critique |
| HRAPI-2026-011 | Fuite de stack traces et d'erreurs Prisma | CWE-209 | 5.3 | Moyenne |
| HRAPI-2026-012 | Upload de fichiers sans restriction de type | CWE-434 | 6.5 | Moyenne |
| HRAPI-2026-013 | Données salariales exposées à des rôles non autorisés | CWE-863 | 6.5 | Moyenne |
| HRAPI-2026-014 | Rate limiting contournable, pas de verrouillage | CWE-307 | 7.5 | Élevée |
| HRAPI-2026-015 | Contrôles d'accès métier manquants (congés, contacts) | CWE-862 | 8.1 | Élevée |
| HRAPI-2026-016 | Intégrité de la paie (montants négatifs, pas d'états) | CWE-840 | 6.5 | Moyenne |
| HRAPI-2026-017 | Changement d'e-mail sans vérification | CWE-620 | 5.4 | Moyenne |
| HRAPI-2026-018 | Énumération d'utilisateurs | CWE-204 | 5.3 | Moyenne |
| HRAPI-2026-019 | Pagination non bornée (DoS) | CWE-770 | 6.5 | Moyenne |
| HRAPI-2026-020 | Injection HTML dans les e-mails | CWE-79 | 5.4 | Moyenne |
| HRAPI-2026-021 | Injection dans l'en-tête `Content-Disposition` | CWE-116 | 4.3 | Moyenne |
| HRAPI-2026-022 | CORS : origine reflétée avec `credentials` | CWE-942 | 5.3 | Moyenne |
| HRAPI-2026-023 | Jetons de reset/vérification stockés en clair | CWE-312 | 5.5 | Moyenne |
| HRAPI-2026-024 | Dépendances vulnérables (64 avis) | CWE-1035 | 7.5 | Élevée |
| HRAPI-2026-025 | Durcissement (logs, conteneur root, Redis) | CWE-16 | 3.9 | Faible |
| HRAPI-2026-027 | Élargissement des permissions par le seed | CWE-732 | 6.5 | Moyenne |

---

## Détail des vulnérabilités

### HRAPI-2026-001 — Jeton de réinitialisation renvoyé dans la réponse HTTP
- **CWE :** CWE-640 (Weak Password Recovery Mechanism)
- **CVSS v3.1 :** 9.8 — Critique — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Composant :** `src/modules/auth/auth.controller.ts:35` ; `auth.service.ts` (`forgotPassword`)
- **Description :** `POST /auth/forgot-password` renvoie `debugToken`, le jeton de réinitialisation en clair, sans condition d'environnement. La route n'exige aucune authentification et n'a pas de rate limit.
- **Impact :** prise de contrôle de n'importe quel compte à partir de la seule adresse e-mail, y compris les comptes `ORGANIZATION_ADMIN`.
- **Remédiation :** supprimer `debugToken` ; au besoin le limiter à `NODE_ENV === "test"` et le logger côté serveur ; appliquer `authRateLimit`.

### HRAPI-2026-002 — Sélection du tenant via en-tête `X-Organization-Id`
- **CWE :** CWE-639 (Authorization Bypass Through User-Controlled Key)
- **CVSS v3.1 :** 9.1 — Critique — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
- **Composant :** `src/modules/employees/employee.controller.ts:7-12`
- **Description :** `orgId()` privilégie l'en-tête `x-organization-id` fourni par le client sur `req.auth.organizationId`, pour `listEmployees` et `createEmployee`.
- **Impact :** un utilisateur avec `employee:view` peut lister les employés (et salaires) de toute autre organisation et y créer des employés. Rupture de l'isolation entre tenants.
- **Remédiation :** supprimer la lecture de l'en-tête ; l'organisation vient du contexte authentifié ; n'autoriser l'override que pour `SUPER_ADMIN`.

### HRAPI-2026-003 — Élévation de privilèges vers `SUPER_ADMIN`
- **CWE :** CWE-269 (Improper Privilege Management)
- **CVSS v3.1 :** 9.9 — Critique — `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`
- **Composant :** `src/modules/roles/role.routes.ts:27` ; `role.service.ts` (`setSystemRole`, `assignRole`, `updateRole`, `deleteRole`, `revokeAssignment`)
- **Description :** `PUT /roles/users/:userId/system-role` n'exige que `role:manage` (détenue par tout `ORGANIZATION_ADMIN`, donc par quiconque s'inscrit) et accepte `SUPER_ADMIN`. Aucune vérification d'organisation sur l'utilisateur ou le rôle cible.
- **Impact :** auto-promotion `SUPER_ADMIN` (accès à toute la plateforme) puis modification des rôles d'autres tenants.
- **Remédiation :** interdire l'attribution de `SUPER_ADMIN` et de tout rôle supérieur au sien ; vérifier l'organisation sur chaque opération.

### HRAPI-2026-004 — IDOR généralisés / absence d'isolation multi-tenant
- **CWE :** CWE-639 (Authorization Bypass Through User-Controlled Key) ; connexe CWE-284
- **CVSS v3.1 :** 9.1 — Critique — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
- **Composant :** tous les services ; accès par identifiant sur employés, départements/équipes, congés, paie, performance, documents, notifications
- **Description :** les listes filtrent par organisation, mais les accès par identifiant font `findUnique`/`update`/`delete` par `id` sans vérifier l'organisation. Les UUID circulent dans de nombreuses réponses.
- **Impact :** lecture et modification des données RH, salaires, contrats, numéros d'identité nationaux, bulletins et évaluations de toutes les organisations ; suppression d'employés et de départements ; approbation de paies étrangères.
- **Remédiation :** injecter `organizationId` dans toutes les clauses `where` (ou vérification + 404) ; centraliser via extension Prisma `$extends` ou RLS PostgreSQL ; tests cross-tenant par route.

### HRAPI-2026-005 — Contrôle d'appartenance absent sur `organizations/:id`
- **CWE :** CWE-639
- **CVSS v3.1 :** 9.1 — Critique — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
- **Composant :** `src/modules/organizations/organization.routes.ts:23-24` et suivantes ; `organization.service.ts`
- **Description :** `GET /organizations/:id` et `/:id/stats` sans permission ; `PATCH /:id`, `PUT /:id/settings`, `PUT /:id/subscription`, `GET/POST /:id/admins` vérifient la permission mais pas que `:id` est l'organisation de l'appelant. `updateSubscription` ouvert à `ORGANIZATION_ADMIN`.
- **Impact :** ajout d'un administrateur dans n'importe quelle organisation (prise de contrôle du tenant), désactivation, modification des paramètres et de l'abonnement, lecture d'informations.
- **Remédiation :** exiger `req.params.id === req.auth.organizationId` hors `SUPER_ADMIN` ; réserver l'abonnement au `SUPER_ADMIN`/flux de facturation.

### HRAPI-2026-006 — Téléchargement de documents sans autorisation
- **CWE :** CWE-862 (Missing Authorization)
- **CVSS v3.1 :** 8.1 — Élevée — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N`
- **Composant :** `src/modules/documents/document.routes.ts:25` ; `document.service.ts` (`readDocumentFile`)
- **Description :** `GET /documents/:id/download` sans `requirePermission` et sans contrôle d'organisation.
- **Impact :** tout utilisateur authentifié, de tout tenant, télécharge les contrats et pièces de tous les employés.
- **Remédiation :** ajouter `requirePermission(DOCUMENT_VIEW)` + filtre d'organisation ; vérifier que le chemin résolu reste sous `storageRoot()`.

### HRAPI-2026-007 — SSRF via `import-from-url`
- **CWE :** CWE-918 (Server-Side Request Forgery)
- **CVSS v3.1 :** 9.1 — Critique — `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:L`
- **Composant :** `src/modules/documents/document.service.ts:77`
- **Description :** l'URL fournie est récupérée côté serveur sans restriction (schéma, hôte, IP résolue, 5 redirections suivies, pas de limite de taille). La réponse est stockée puis téléchargeable (SSRF « full read »). La permission requise est `document:manage` (rôle non-admin). Aggravée par les CVE d'axios (HRAPI-2026-024).
- **Impact :** accès aux services internes (Redis, PostgreSQL), aux métadonnées cloud (identifiants IAM), scan du réseau interne.
- **Remédiation :** liste blanche de domaines ; `https` uniquement ; refus des IP privées/loopback/link-local/réservées (IPv4 et IPv6) vérifié à chaque redirection ou redirections désactivées ; `maxContentLength` ; proxy de sortie dédié. Sinon, retirer la fonctionnalité.

### HRAPI-2026-026 — Écriture de fichiers arbitraires via `fileName` (path traversal)
- **CWE :** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory) ; connexe CWE-434
- **CVSS v3.1 :** 9.1 — Critique — `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H`
- **Composant :** `src/modules/documents/document.service.ts` (`importFromUrl`) ; `document.validation.ts` (`importFromUrlSchema.fileName`)
- **Description :** `fileName` n'est validé qu'en longueur (≤ 200). Il est concaténé dans `storedName` puis passé à `path.join(uploadsDir(), storedName)` ; `path.join` normalise les séquences de remontée, si bien que le chemin peut sortir de `storage/uploads/`. `fs.writeFileSync` écrit un contenu entièrement contrôlé par l'appelant (réponse de l'URL fournie) et écrase un fichier existant. Le `storagePath` enregistré suit le même chemin, donc `DELETE /documents/:id` peut aussi supprimer hors du répertoire. Le `Dockerfile` ne fixe pas d'utilisateur : en conteneur, le processus tourne en root.
- **Impact :** écriture/écrasement de fichiers arbitraires là où le processus a le droit d'écrire (code applicatif, configuration), menant à une exécution de code côté serveur ; suppression de fichiers hors périmètre. Accessible à un rôle non-admin (`document:manage`).
- **Remédiation :** assainir `fileName` (retirer tout séparateur et séquence de remontée, conserver le seul basename) ; résoudre le chemin final avec `path.resolve` et vérifier `startsWith(uploadsDir())` ; appliquer la même vérification au `storagePath` avant lecture/suppression ; exécuter le conteneur en utilisateur non privilégié.

### HRAPI-2026-008 — Sessions non révocables, refresh token rejouable
- **CWE :** CWE-613 (Insufficient Session Expiration) ; connexe CWE-384
- **CVSS v3.1 :** 8.1 — Élevée — `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`
- **Composant :** `src/middleware/authenticate.ts` ; `auth.service.ts` (`refresh`, `logout`, `resetPassword`, `changePassword`)
- **Description :** `authenticate` ne vérifie jamais `session.revokedAt` (logout et `DELETE /sessions/:id` sans effet sur les access tokens). `refresh` n'invalide pas l'ancien jeton (remplit seulement `replacedBy`) et ne détecte pas la réutilisation ; il met `sessionId = tokenId`. Reset et changement de mot de passe ne révoquent ni sessions ni refresh tokens.
- **Impact :** un jeton volé reste utilisable jusqu'à 14 jours en parallèle du légitime ; impossibilité de déconnecter un compte compromis.
- **Remédiation :** vérifier la session (cache Redis) ; rotation stricte avec révocation du jeton consommé et de la famille en cas de réutilisation ; propager le vrai `sessionId` ; tout révoquer après changement/reset.

### HRAPI-2026-009 — Rôle et organisation lus depuis le JWT
- **CWE :** CWE-807 (Reliance on Untrusted Inputs in a Security Decision)
- **CVSS v3.1 :** 7.5 — Élevée — `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N`
- **Composant :** `src/middleware/authenticate.ts` ; `src/utils/jwt.ts`
- **Description :** `role` et `organizationId` sont pris dans le payload du JWT. Une rétrogradation ou un changement d'organisation ne s'applique qu'à l'expiration. `verifyAccessToken` ne fixe pas `algorithms` et ne vérifie pas toujours `type === "access"`.
- **Impact :** persistance de privilèges révoqués ; en cas de compromission du secret (HRAPI-2026-010), choix libre du rôle.
- **Remédiation :** utiliser `user.systemRole`/`user.organizationId` depuis la base ; `jwt.verify(..., { algorithms: ["HS256"] })` ; vérifier `type`, `iss`, `aud`.

### HRAPI-2026-010 — Secrets JWT par défaut codés en dur
- **CWE :** CWE-798 (Use of Hard-coded Credentials) ; connexe CWE-453
- **CVSS v3.1 :** 9.8 — Critique — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Composant :** `src/config/env.ts:27-28` ; `docker-compose.yml`
- **Description :** `required("JWT_ACCESS_SECRET", "dev-access-secret-change-me")` fournit une valeur par défaut (jamais d'échec). Le compose définit `change-me-access`/`change-me-refresh`. Un déploiement non configuré utilise des secrets publics.
- **Impact :** forge de jetons `SUPER_ADMIN` arbitraires.
- **Remédiation :** aucune valeur par défaut en production (échec au démarrage) ; longueur minimale ≥ 32 octets aléatoires ; secrets via un gestionnaire de secrets.

### HRAPI-2026-011 — Fuite de stack traces et d'erreurs Prisma
- **CWE :** CWE-209 (Generation of Error Message Containing Sensitive Information)
- **CVSS v3.1 :** 5.3 — Moyenne — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
- **Composant :** `src/middleware/error.ts:37,51,63`
- **Description :** les erreurs 500 renvoient `message` et `stack` ; les erreurs Prisma renvoient `err.message` et `err.meta` (tables, colonnes, contraintes).
- **Impact :** cartographie interne facilitant d'autres attaques.
- **Remédiation :** message générique + `requestId` en production ; détail dans les logs uniquement.

### HRAPI-2026-012 — Upload de fichiers sans restriction de type
- **CWE :** CWE-434 (Unrestricted Upload of File with Dangerous Type)
- **CVSS v3.1 :** 6.5 — Moyenne — `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L`
- **Composant :** `src/modules/documents/upload.ts:28-35`
- **Description :** `fileFilter` appelle `cb(null, true)` dans les deux branches (liste blanche MIME inopérante). `mimeType` déclaré par le client est stocké puis renvoyé en `Content-Type`. Pas de vérification par signature, pas d'antivirus. Le nom de stockage étant généré côté serveur, il n'y a pas de traversée de chemin par cette route (voir HRAPI-2026-026 pour l'import par URL).
- **Impact :** hébergement de fichiers malveillants transmis à des collaborateurs RH ; XSS stocké si un front sert les fichiers inline ; saturation disque.
- **Remédiation :** `cb(err, false)` hors liste blanche ; vérification par signature (`file-type`) ; extension dérivée du type validé ; `Content-Type` fixé côté serveur ; `nosniff` ; antivirus ; quota.

### HRAPI-2026-013 — Données salariales exposées à des rôles non autorisés
- **CWE :** CWE-863 (Incorrect Authorization)
- **CVSS v3.1 :** 6.5 — Moyenne — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **Composant :** `src/modules/reports/report.routes.ts:41` ; `workers/report.worker.ts` ; `employee.service.ts` (`getEmployee`, `listEmployees`)
- **Description :** `GET /reports/dashboard` (`report:view`) inclut `salarySummary` ; `POST /reports/export` avec `reportType: "salary-summary"` contourne le contrôle `salary:view`. `GET /employees/:id` renvoie salaire, contrats, `nationalId`, `dateOfBirth`, `address` à un `DEPARTMENT_MANAGER`.
- **Impact :** accès à la masse salariale et aux données personnelles sensibles sans la permission adéquate.
- **Remédiation :** projections selon permissions ; retirer le salaire du dashboard ou le conditionner à `salary:view` ; valider `reportType` par liste blanche avec contrôle de permission.

### HRAPI-2026-014 — Rate limiting contournable, pas de verrouillage
- **CWE :** CWE-307 (Improper Restriction of Excessive Authentication Attempts)
- **CVSS v3.1 :** 7.5 — Élevée — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L`
- **Composant :** `src/app.ts:18` ; `src/middleware/rateLimit.ts`
- **Description :** `trust proxy: true` fait confiance à tout `X-Forwarded-For` ; la clé du limiteur d'auth combine IP et e-mail (contournable par variation) ; `register`, `forgot-password`, `reset-password`, `refresh`, `verify-email` sans limiteur ; fail-open si Redis tombe ; `failedLoginCount` jamais exploité.
- **Impact :** credential stuffing et brute force non entravés ; pas de verrouillage de compte.
- **Remédiation :** `trust proxy` = nombre de proxys exact ou liste d'IP ; limiteurs par IP et par compte ; verrouillage temporaire et délai progressif ; fail-closed sur l'authentification.

### HRAPI-2026-015 — Contrôles d'accès métier manquants
- **CWE :** CWE-862 (Missing Authorization) ; connexe CWE-639
- **CVSS v3.1 :** 8.1 — Élevée — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
- **Composant :** `leave.routes.ts:23,26` ; `employee.routes.ts:28` ; `performance.service.ts`
- **Description :** `POST /employees/:id/emergency-contacts` sans permission ; `POST /leave/requests` sans permission ni contrôle de propriété ; `POST /leave/requests/:id/cancel` sans permission (annulation de toute demande, même `APPROVED`, sans recréditer le solde) ; auto-approbation de congés possible ; `PATCH /performance/reviews/:id` permet de passer en `FINALIZED` sans vérifier l'auteur ni l'état.
- **Impact :** modification de fiches d'autrui, congés frauduleux, falsification d'évaluations.
- **Remédiation :** contrôles de propriété/hiérarchie, transitions d'état validées, interdiction de l'auto-approbation.

### HRAPI-2026-016 — Intégrité de la paie
- **CWE :** CWE-840 (Business Logic Errors) ; connexe CWE-20
- **CVSS v3.1 :** 6.5 — Moyenne — `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N`
- **Composant :** `src/modules/payroll/payroll.validation.ts:16` ; `payroll.service.ts`
- **Description :** `adjustmentSchema.amount = z.number()` (bonus/déductions négatifs, montants illimités) ; aucune machine à états (`approve` sans `submit`, `pay` sans `approve`, bonus sur paie `PAID`) ; pas de séparation des tâches ; calcul en flottant au lieu de `Decimal`.
- **Impact :** manipulation des montants nets, versements frauduleux, incohérences de statut.
- **Remédiation :** `amount: z.number().positive().max(...)` ; transitions vérifiées ; approbateur ≠ créateur ; arithmétique en `Prisma.Decimal`.

### HRAPI-2026-017 — Changement d'e-mail sans vérification
- **CWE :** CWE-620 (Unverified Password Change) ; connexe CWE-345
- **CVSS v3.1 :** 5.4 — Moyenne — `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`
- **Composant :** `src/modules/auth/auth.service.ts` (`updateProfile`, `login`, `forgotPassword`)
- **Description :** `PATCH /auth/me` change l'e-mail sans ressaisie de mot de passe ni vérification, sans remettre `emailVerified` à `false`. Unicité `@@unique([organizationId, email])` mais `login`/`forgotPassword` utilisent `findFirst({ where: { email } })` sans organisation (compte choisi indéterminé). `emailVerified` jamais exigé à la connexion.
- **Impact :** confusion de comptes, reset dirigé vers le mauvais compte, détournement d'adresse.
- **Remédiation :** unicité globale ou login avec slug d'organisation ; flux de changement d'e-mail avec confirmation ; ré-authentification.

### HRAPI-2026-018 — Énumération d'utilisateurs
- **CWE :** CWE-204 (Observable Response Discrepancy)
- **CVSS v3.1 :** 5.3 — Moyenne — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
- **Composant :** `src/modules/auth/auth.service.ts` (`register`, `login`, `forgotPassword`)
- **Description :** 409 explicite à l'inscription ; `login` répond plus vite si le compte n'existe pas (pas de vérification argon2) ; `forgot-password` répond différemment (HRAPI-2026-001).
- **Impact :** constitution de listes d'adresses valides pour phishing/brute force ciblé.
- **Remédiation :** réponses et temps uniformes (hash factice) ; message générique à l'inscription.

### HRAPI-2026-019 — Pagination non bornée
- **CWE :** CWE-770 (Allocation of Resources Without Limits or Throttling)
- **CVSS v3.1 :** 6.5 — Moyenne — `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H`
- **Composant :** `src/utils/pagination.ts:13`
- **Description :** `pageSize` sans minimum ni maximum ; une grande valeur charge des tables entières avec jointures ; une valeur ≤ 0 provoque des erreurs Prisma (fuite via HRAPI-2026-011). `listDocuments`, `listReviews`, `departmentCalendar` sans pagination.
- **Impact :** déni de service mémoire/base.
- **Remédiation :** `clamp(pageSize, 1, 100)`.

### HRAPI-2026-020 — Injection HTML dans les e-mails
- **CWE :** CWE-79 (Improper Neutralization of Input During Web Page Generation)
- **CVSS v3.1 :** 5.4 — Moyenne — `AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N`
- **Composant :** `src/services/mailer.ts` (`renderTemplate`)
- **Description :** concaténation des valeurs (`firstName`, nom d'organisation, `role` d'invitation) sans échappement. `POST /notifications/invite` envoie à une adresse quelconque avec un `role` libre.
- **Impact :** phishing/HTML injecté dans des e-mails émis depuis le domaine officiel.
- **Remédiation :** moteur de templates à échappement automatique ; liste blanche pour `role` ; limite d'envoi.

### HRAPI-2026-021 — Injection dans l'en-tête `Content-Disposition`
- **CWE :** CWE-116 (Improper Encoding or Escaping of Output) ; connexe CWE-93
- **CVSS v3.1 :** 4.3 — Moyenne — `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`
- **Composant :** `src/modules/documents/document.controller.ts:39`
- **Description :** `originalName` (fourni par le client) est interpolé entre guillemets sans échappement. Les guillemets et points-virgules permettent de manipuler le nom ou les paramètres.
- **Impact :** manipulation du nom de fichier restitué, confusion possible côté client.
- **Remédiation :** `res.attachment(name)` / `content-disposition` avec encodage RFC 5987 ; assainir le nom.

### HRAPI-2026-022 — CORS : origine reflétée avec `credentials`
- **CWE :** CWE-942 (Permissive Cross-domain Policy with Untrusted Domains)
- **CVSS v3.1 :** 5.3 — Moyenne — `AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N`
- **Composant :** `src/app.ts:23`
- **Description :** avec `CORS_ORIGIN=*` (défaut), `origin: true` reflète toute origine avec `credentials: true`. Impact direct limité (auth Bearer) mais dangereux dès l'ajout de cookies.
- **Remédiation :** liste explicite d'origines ; pas de valeur par défaut `*`.

### HRAPI-2026-023 — Jetons de reset/vérification stockés en clair
- **CWE :** CWE-312 (Cleartext Storage of Sensitive Information)
- **CVSS v3.1 :** 5.5 — Moyenne — `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **Composant :** `prisma/schema.prisma` (`PasswordResetToken`, `EmailVerificationToken`) ; `auth.service.ts`
- **Description :** jetons stockés et recherchés en clair ; le token de vérification passe en query string (`GET /verify-email`) et finit dans les logs d'accès.
- **Impact :** une fuite de base ou de logs donne des jetons directement exploitables.
- **Remédiation :** stocker `sha256(token)` ; usage unique (déjà en place) ; durée courte.

### HRAPI-2026-024 — Dépendances vulnérables
- **CWE :** CWE-1035 / CWE-1395 (Dependency on Vulnerable Third-Party Component)
- **CVSS v3.1 :** 7.5 — Élevée — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L` (score représentatif du composant le plus exposé, axios)
- **Composant :** `package.json` ; `pnpm audit` → 64 avis (4 critiques, 21 élevés, 35 modérés, 4 faibles)
- **Description :**

| Paquet | Gravité max | CVE/avis notables | Remarque |
|---|---|---|---|
| `axios` 1.7.7 | élevée | SSRF, DoS `data:`, prototype pollution | aggrave HRAPI-2026-007 ; passer en ≥ 1.15.1 |
| `path-to-regexp` (express 4.21.1) | élevée | ReDoS | mettre à jour express |
| `body-parser`, `qs` (express) | élevée | — | mettre à jour express |
| `zod` 3.23.8 | élevée | — | mettre à jour |
| `nanoid` 3.3.7 | élevée | — | mettre à jour |
| `multer` 1.4.5-lts.1 | — | DoS connus | migrer en 2.x |
| `vitest`/`tinypool`/`vite`/`esbuild` | critique | RCE si UI vitest exposée | dev uniquement ; vitest ≥ 3.2.6 |

- **Remédiation :** mise à jour des dépendances ; `pnpm audit` en CI.

### HRAPI-2026-025 — Durcissement (configuration et exploitation)
- **CWE :** CWE-16 (Configuration) ; connexes CWE-532, CWE-250
- **CVSS v3.1 :** 3.9 — Faible — `AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L`
- **Composant :** divers (`lib/logger.ts`, `requestContext.ts`, `Dockerfile`, `docker-compose.yml`, `app.ts`)
- **Description :** `pino-http` logue l'en-tête `Authorization` ; Prisma logue les requêtes hors production ; `X-Request-Id` accepté sans validation (log forging) ; mot de passe de seed commun `Password123!` ; `numericCode()` utilise `Math.random()` ; conteneur exécuté en root ; PostgreSQL/Redis exposés sur l'hôte ; Redis sans mot de passe ; identifiants `hr/hr` ; `express.json` limité à 5 Mo ; cache `org:<id>` servi à tout appelant ; route `accept-invite` inexistante (jeton d'invitation jamais stocké) ; audit logs stockant le corps complet des mises à jour (PII).
- **Remédiation :** redaction des logs ; validation de `X-Request-Id` ; conteneur non-root ; Redis avec mot de passe/ACL ; ports DB non exposés ; politique de mots de passe ; aléa cryptographique.

### HRAPI-2026-027 — Élargissement des permissions par le seed
- **CWE :** CWE-732 (Incorrect Permission Assignment for Critical Resource) ; connexe CWE-266
- **CVSS v3.1 :** 6.5 — Moyenne — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- **Composant :** `prisma/seed.ts` (rôle « Custom HR Operations »)
- **Description :** le seed crée un rôle personnalisé cumulant les permissions `employee:*`, `leave:*` et `document:*`, et l'attribue aux comptes spéciaux de chaque organisation. Des rôles censés être restreints (`DEPARTMENT_MANAGER`, `FINANCE_MANAGER`) obtiennent ainsi `document:manage`, ce qui élargit la surface exploitable de HRAPI-2026-007 et HRAPI-2026-026 au-delà des seuls administrateurs.
- **Impact :** des comptes non-admin disposent de permissions sensibles (gestion de documents, donc import par URL) ; cumul de permissions non voulu en production si le même schéma d'attribution est repris.
- **Remédiation :** définir les rôles personnalisés selon le principe du moindre privilège ; ne pas accorder `document:manage` par défaut à des rôles d'encadrement ; séparer clairement données de seed et configuration de production.

---

## Analyse approfondie — chaîne « write-to-RCE » (HRAPI-2026-026)

Cette section documente comment la primitive d'écriture de fichier arbitraire
se transforme en exécution de code côté serveur. Il s'agit d'une **analyse de
risque** destinée aux développeurs, pas d'un mode opératoire ni d'un exploit
clé en main.

### Primitive de départ

`POST /documents/import-from-url` réunit deux propriétés :

1. **Contenu entièrement contrôlé par l'appelant** — le corps écrit sur disque
   est la réponse HTTP de l'URL fournie. L'attaquant héberge son propre serveur
   et renvoie un contenu arbitraire (y compris du JavaScript valide).
2. **Emplacement contrôlé** — `fileName` n'est validé qu'en longueur ; `path.join`
   normalise les séquences `../`, donc le chemin d'écriture peut sortir de
   `storage/uploads/` et viser n'importe quel emplacement accessible en écriture
   au process. L'écriture **écrase** un fichier existant.

Primitive obtenue : **écriture/écrasement de fichier, contenu + chemin
contrôlés.**

### Le maillon manquant : un sink « write → execute »

L'application n'exécute aucun fichier depuis `uploads/`. La RCE n'est donc pas
directe : elle suppose d'écrire dans un emplacement que le runtime **relit et
exécute**. Candidats, par ordre de vraisemblance :

| Cible écrasée | Pourquoi c'est exécuté | Déclencheur |
|---|---|---|
| un `.js` sous `dist/` (code compilé de l'app) | chargé par Node au boot ou au `require` | redémarrage du process |
| un fichier d'un paquet dans `node_modules/` chargé au runtime | idem | redémarrage du process |
| un fichier de configuration lu au démarrage | parsé/évalué au boot | redémarrage du process |

Le contenu étant contrôlé (point 1) et l'emplacement aussi (point 2), planter un
module JavaScript sous le répertoire applicatif est réalisable. L'exécution
survient au **prochain démarrage** du process.

### Facteurs aggravants (packaging livré)

- Le `Dockerfile` ne définit pas d'utilisateur (`USER`) : le process tourne en
  **root**, donc l'écriture atteint tout le système de fichiers du conteneur et
  le code s'exécute avec les privilèges maximaux.
- Le système de fichiers applicatif n'est pas monté en lecture seule.
- Les redémarrages sont fréquents en production (déploiement, crash,
  orchestrateur qui recrée des pods/workers), ce qui rend le déclencheur banal.

### Nature et limites

- Il s'agit d'une **RCE « write-to-execute sur redémarrage »**, pas d'une
  exécution instantanée en mémoire : le code planté s'exécute au prochain boot,
  pas à l'instant de l'écriture.
- Aucune RCE **instantanée** n'a été trouvée dans le code applicatif : pas de
  `eval`/`Function`/`vm`/`child_process`, pas de `require` dynamique sur chemin
  contrôlé, pas de désérialisation dangereuse, pas de moteur de template serveur
  (donc pas de SSTI). Les RCE critiques de `vitest`/`tinypool` (HRAPI-2026-024)
  sont **dev-only** et ne concernent pas l'API en production.

### Prérequis d'accès

`import-from-url` exige `document:manage`. Un compte `EMPLOYEE` ne l'a pas
(réponse 403 vérifiée) : il doit d'abord escalader — par forge de jeton si le
secret JWT est par défaut (HRAPI-2026-010) ou par prise de contrôle d'un compte
privilégié (HRAPI-2026-001). À cause du seed (HRAPI-2026-027), certains rôles
d'encadrement disposent de `document:manage` sans être administrateurs, ce qui
élargit la population capable d'atteindre ce sink.

### Remédiation (prioritaire)

1. **Assainir `fileName`** : conserver le seul `path.basename`, rejeter toute
   occurrence de `..` ou de séparateur de chemin.
2. **Confiner l'écriture** : construire le chemin avec `path.resolve` puis
   vérifier `resolved.startsWith(uploadsDir())` avant toute écriture ; appliquer
   le même contrôle à `storagePath` en lecture et suppression.
3. **Réduire le rayon d'action** : exécuter le conteneur en utilisateur non
   privilégié, monter le code applicatif en lecture seule, isoler le stockage
   des uploads sur un volume distinct non exécutable.
4. **Encadrer la fonctionnalité** : liste blanche de domaines, protection SSRF
   (HRAPI-2026-007), limite de taille, ou suppression de l'import par URL si le
   besoin métier ne la justifie pas.

## Correspondance avec OWASP API Security Top 10 (2023)

| Catégorie OWASP | Failles concernées |
|---|---|
| API1 Broken Object Level Authorization | 002, 004, 005, 006, 026 |
| API2 Broken Authentication | 001, 008, 010, 014, 018, 023 |
| API3 Broken Object Property Level Authorization | 013 |
| API5 Broken Function Level Authorization | 003, 015, 027 |
| API6 Unrestricted Access to Sensitive Business Flows | 016 |
| API7 Server Side Request Forgery | 007 |
| API8 Security Misconfiguration | 009, 011, 020, 021, 022, 025 |
| API10 Unsafe Consumption / composants vulnérables | 024 |
| Hors liste (upload / DoS) | 012, 017, 019, 026 |
