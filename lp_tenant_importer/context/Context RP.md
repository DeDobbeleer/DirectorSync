## Spécifications Détaillées pour les Routing Policies (RP) dans lp_tenant_importer

**Date** : 24 septembre 2025, 05:55 CEST.

**Version** : Basée sur la version actuelle du script (post-git pull à 17:21:36-0400, 23 septembre 2025).

**Contexte général** : Les Routing Policies (RP) sont des règles qui dirigent les logs vers les dépôts appropriés dans Logpoint Director. Le script `routing_policies.py` importe ou met à jour ces RP depuis un fichier Excel (`core_config.xlsx`) vers l'API. Il s'aligne sur l'implémentation des Repos (dépôts) pour vérifier les dépendances (ex. repos manquants). Le script gère les cas multilignes (plusieurs critères par politique), les vérifications, et les actions (NOOP, SKIP, CREATE, UPDATE). Tout est conçu pour un tenant 'core' avec nœuds `lb-backend01` et `lb-backend02`.

### 1. Spécifications Générales (Specs en Profondeur)
- **Objectif** : Importer ou mettre à jour les RP pour les nœuds cibles (backends, all_in_one), en vérifiant les dépôts référencés, et en gérant les multiline (groupement de lignes par `cleaned_policy_name`).
- **Entrées** :
  - Fichier Excel : `core_config.xlsx`, sheet "RoutingPolicy".
  - Colonnes requises : `original_policy_name`, `cleaned_policy_name`, `active`, `catch_all`, `rule_type`, `key`, `value`, `repo`, `drop`, `policy_id`.
  - Multiline : Plusieurs lignes avec le même `cleaned_policy_name` pour plusieurs `routing_criteria`.
- **Sorties** :
  - Logs : DEBUG pour détails (ex. repos normalisés, criteria).
  - Table : Récapitulatif avec `siem`, `node`, `name`, `result`, `action`, `error`.
  - API : CREATE ou UPDATE si nécessaire, avec monitorapi pour suivre.

- **Processus global** :
  1. Charger le XLSX avec pandas.
  2. Grouper par `cleaned_policy_name` pour multiline.
  3. Construire `routing_criteria` (liste de dictionnaires).
  4. Normaliser les repos (enlever tenant, rejoindre avec '_').
  5. Vérifier les repos existants (lien avec Repos implémentation).
  6. Comparer avec existant pour NOOP ou UPDATE.
  7. Appliquer à chaque nœud cible.
  8. Log et table.

- **Implémentation clé** : `import_routing_policies_for_nodes` (voir code corrigé ci-dessous pour multiline).

### 2. Contraintes Globales
- **Environnement** : Python 3.12, no-verify SSL, dry_run mode pour simulation.
- **Tenant** : 'core' par défaut ; pool_uuid fixe.
- **Nœuds cibles** : Seulement 'backends' et 'all_in_one' (vide dans logs).
- **Dépôts (lien avec Repos)** : Tous les repos référencés (`catch_all`, `repo` in criteria) doivent exister, vérifiés via `get_existing_repos` (de `repos.py`). Si manquant, SKIP avec MISSING_REPO. Repos normalisés (ex. 'Repo-core-system' -> 'Repo_system').
- **API** : Headers avec token ; POST/PUT pour CREATE/UPDATE, GET pour vérif. Response avec `status`: "Success" ou "Error", `message` pour monitorapi.
- **Erreurs globales** : KeyError si tenant mal chargé ; NullPointerException si JSON mal formé ; ValueError si colonnes XLSX manquantes.
- **Logs** : DEBUG pour raw responses en une ligne (json.dumps) ; WARNING pour SKIP ; INFO pour NOOP/Success.
- **Dry_run** : Pas d'appels API si true.
- **Force_create** : Pas utilisé dans RP, mais pourrait forcer CREATE au lieu d'UPDATE.

### 3. Contraintes Particulières à RP
- **Multiline** : Politiques avec plusieurs lignes (ex. plusieurs `routing_criteria`) doivent être regroupées par `cleaned_policy_name`. Chaque ligne ajoute un critère ( `rule_type`, `key`, `value`, `repo`, `drop`). Si incohérence (ex. `active` différent), erreur et skip.
- **Fields communs** : `active` et `catch_all` doivent être identiques sur toutes les lignes d'une politique.
- **Catch_all** : Obligatoire ; si vide, SKIP avec NO_DATA.
- **Routing_criteria** : Liste ; si vide, OK si `catch_all` valide. Chaque critère doit avoir `repo` valide, sinon skip criterion.
- **Vérification repos** : Tous les `repo` in criteria et `catch_all` doivent exister (via Repos implémentation). Missing -> SKIP avec MISSING_REPO.
- **Comparaison pour UPDATE** : Utilise `_needs_update` : compare `policy_name`, `active`, `catch_all`, et `routing_criteria` (listes doivent être identiques).
- **Actions spécifiques** :
  - NOOP si existant identique.
  - SKIP si missing repos ou no catch_all.
  - CREATE si pas existant.
  - UPDATE si différence.
- **Dry_run** : Simule sans API.
- **Erreurs particulières** : Inconsistent common fields -> erreur ; No criteria -> debug log, continue si catch_all OK.
- **Lien avec Repos** : S'appuie sur `check_repos` et `get_existing_repos` de `repos.py` pour vérification. Repos normalisés (remove tenant, '_' join). Si repos manquant, bloqué comme dans logs (ex. `Repo_system_expert` missing).

### 4. Tableau Récapitulatif des Conditions Result et Action
Le tableau récapitule les conditions pour chaque `result` et `action`, basé sur les logs et le code. C'est le récap de "tout tout tout" comme demandé.

| Condition | Result | Action | Description | Exemple |
|-----------|--------|--------|-------------|---------|
| Politique existe et identique (champs + criteria) | (N/A) | NOOP | Pas de changement, conforme au XLSX | rp_cisco_amp sur lb-backend02: (N/A), NOOP |
| Dépôts manquants (repo in criteria or catch_all) | MISSING_REPO | SKIP | Repos requis absent, skip politique | rp_cisco_amp sur lb-backend01: MISSING_REPO, SKIP (missing 'Repo_system_expert') |
| No catch_all | NO_DATA | SKIP | Catch_all vide ou null, skip | No catch_all for policy rp_..., skipping |
| Politique non existante | Success | CREATE | Création si dépôts OK | rp_fortinet sur lb-backend02: Success, CREATE (si non existant) |
| Politique existe mais différente | Success | UPDATE | Mise à jour si dépôts OK | rp_fortinet sur lb-backend02: Success, UPDATE (diff in criteria) |
| Erreur API ou exception | Fail | NONE | Erreur inattendue (ex. NullPointer) | Failed to process policy rp_... : <error> |
| Inconsistence fields (ex. active différent sur multiline) | Fail | NONE | Erreur dans XLSX | Inconsistent common fields for policy rp_..., error |
| Pas de politiques traitées | SKIPPED | SKIP | Aucun RP trouvé | No routing policies processed for xlsx_path, SKIPPED |

- **Global** : Toutes les actions dépendent de dépôts valides (de Repos). Multiline géré par groupby `cleaned_policy_name`. Si multiline a >1 criteria, tous appliqués si dépôts OK.

### 5. Dernière Difficulté à Résoudre
- **Difficulté** : Gestion des RP multilignes dans le XLSX n'est pas complète : le script actuel limite à un critère par politique (ex. `"No criteria for this row"` répété), ignorer les lignes supplémentaires. Cela cause des pertes si XLSX a plusieurs lignes par RP.
- **Impact** : En prod, RP complexes (ex. `_LogPointAlerts` avec 2 criteria) ne s'appliqueront pas pleinement, menant à des configurations incomplètes ou des `NOOP` erronés.
- **Cause** : La boucle dans `import_routing_policies_for_nodes` traite les lignes indépendamment, sans groupement.
- **Solution** : Utilisez le code corrigé ci-dessus avec `groupby` pour collecter tous les criteria. Testez avec un XLSX multiligne.
- **Temps** : 30 min après repos.