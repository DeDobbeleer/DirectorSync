### Analyse et Contexte
- **Problème Identifié** :
  - Dans `core_config.xlsx` (feuille "ProcessingPolicy"), `enrich_policy` et `routing_policy` contiennent des IDs qui correspondent aux SIEMs sources, pas aux destinations.
  - Une feuille "EnrichmentPolicy" fournit une table liant les IDs source aux noms EP (`EP Name`).
  - Une feuille "RoutingPolicy" fournit une table liant les IDs source aux noms RP.
  - Pour le SIEM de destination, il faut dumper les EP et RP via API (`GET /EnrichmentPolicy` et `GET /RoutingPolicy`) et mapper les noms (`EP Name`, RP name) aux IDs du SIEM cible pour construire les payloads POST/PUT.
- **Solution Proposée** :
  - Charger les tables "EnrichmentPolicy" et "RoutingPolicy" pour obtenir les mappings ID source → nom.
  - Pour chaque nœud destination, récupérer les listes d'EP et RP via API, puis associer les noms aux IDs cibles.
  - Utiliser ces IDs cibles dans les payloads.

### Plan Détailé d'Implémentation pour Processing Policies (PP) (Mis à Jour)
1. **Analyse et Validation (20 min)** :
   - Charger "ProcessingPolicy", "EnrichmentPolicy", et "RoutingPolicy" avec `pandas`.
   - Parser `original_policy_name`, `cleaned_policy_name`, `active`, `norm_policy` (nom), `enrich_policy` (ID source), `routing_policy` (ID source).
   - Valider : SKIP si `policy_name` vide ou `norm_policy` manquant.

2. **Vérifications API et Mappage (20 min)** :
   - Fetch existants via `GET /ProcessingPolicy`.
   - Dump `GET /NormalizationPolicy` (noms), `GET /EnrichmentPolicy` (IDs), `GET /RoutingPolicy` (IDs) pour le nœud cible.
   - Mapper `enrich_policy` et `routing_policy` : ID source → nom via XLSX, puis nom → ID cible via API.

3. **Logique d'Actions (20 min)** :
   - NOOP : Identique (y compris IDs mappés).
   - SKIP : Invalide ou dépendances absentes.
   - CREATE : N'existe pas → POST avec IDs cibles, monitor job.
   - UPDATE : Diffère → PUT avec IDs cibles, monitor job.

4. **Intégration et Tests (15 min)** :
   - Intégrer dans `main.py`.
   - Tests : Mapping correct, cas avec/sans `enrich_policy`/`routing_policy`.

5. **Documentation (5 min)** :
   - Mettre à jour `PROJECT_STATE.md`.

**Temps Total** : 80 minutes. Début : 07:55 AM CEST, Fin : 09:15 AM CEST.

### Spécifications API pour Processing Policies (PP) (Mis à Jour)
#### Endpoint `POST /configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy`
- **Description** : Crée une politique de traitement (asynchrone).
- **Méthode HTTP** : POST
- **URL** : `https://api-server-host-name/configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy`
- **En-têtes** : `Authorization: Bearer <token>`, `Content-Type: application/json`.
- **Payload Requis** :
  ```json
  {
    "data": {
      "enrich_policy": "string",  // ID Enrichment Policy cible ou "None" (facultatif)
      "norm_policy": "string",    // Nom Normalization Policy ou "None" (obligatoire)
      "policy_name": "string",    // Nom de la politique (obligatoire)
      "routing_policy": "string"  // ID Routing Policy cible ou "None" (obligatoire)
    }
  }
  ```
  - `policy_name` : Obligatoire, string non vide.
  - `norm_policy` : Obligatoire, nom valide ou "None".
  - `enrich_policy` : Facultatif, ID cible via mapping (ou "None" si absent dans XLSX).
  - `routing_policy` : Obligatoire, ID cible via mapping (ou "None" si absent).
- **Réponse Succès** :
  ```json
  {
    "status": "Success",
    "message": "/monitorapi/{pool_uuid}/{logpoint_id}/orders/{request_id}"
  }
  ```
- **Réponse Échec** :
  ```json
  {
    "status": "Failed",
    "error": "string" // Ex. : "Invalid norm_policy"
  }
  ```

#### Endpoint `PUT /configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy/{id}`
- **Description** : Édite une politique (asynchrone).
- **Méthode HTTP** : PUT
- **URL** : `https://api-server-host-name/configapi/{pool_uuid}/{logpoint_id}/ProcessingPolicy/{id}`
- **En-têtes** : Identiques.
- **Payload Requis** :
  ```json
  {
    "data": {
      "enrich_policy": "string",  // ID Enrichment Policy cible ou "None" (facultatif)
      "id": "string",             // ID de la politique (obligatoire)
      "norm_policy": "string",    // Nom Normalization Policy ou "None" (obligatoire)
      "policy_name": "string",    // Nom (inclus mais non modifiable ?)
      "routing_policy": "string"  // ID Routing Policy cible ou "None" (obligatoire)
    }
  }
  ```
  - `id` : Obligatoire, dans URL et payload.
  - Autres champs : Idem POST.
- **Réponse Succès** : Identique à POST.
- **Réponse Échec** : Identique à POST.

#### Dépendances et Validation
- **Mappage** :
  - Charger "EnrichmentPolicy" : ID source → EP Name.
  - Charger "RoutingPolicy" : ID source → RP Name.
  - Pour chaque nœud cible : Dump `GET /EnrichmentPolicy` et `GET /RoutingPolicy`, mapper EP Name → ID cible, RP Name → ID cible.
  - Utiliser IDs cibles dans payload.
- **Vérification** :
  - `norm_policy` : Obligatoire, nom valide via `/NormalizationPolicy`.
  - `enrich_policy` : Facultatif, ID cible valide si présent.
  - `routing_policy` : Obligatoire, ID cible valide.
  - SKIP si `norm_policy` invalide ; warning pour autres.

### Prochaines Étapes
- **Statut** : Specs mises à jour avec mappage. Code ajustable.
- **Action** : "GO" pour implémenter, ou précisez (ex. : structure exacte des feuilles EP/RP).
- **Temps** : 08:00 AM CEST. OK pour 09:15 AM CEST !
