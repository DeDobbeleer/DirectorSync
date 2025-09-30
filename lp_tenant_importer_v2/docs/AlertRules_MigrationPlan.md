Parfait — voilà **comment j’implémenterais l’import “AlertRules”** dans ton **Framework v2** en réutilisant strictement le pipeline `BaseImporter` et le style de `ProcessingPoliciesImporter`, sans code.

# 1) Où s’accrocher dans le pipeline v2

* **Hooks à implémenter** : `validate`, `iter_desired`, `key_fn`, `canon_desired`, `canon_existing`, `fetch_existing`, `build_payload_create`, `build_payload_update`, `apply`. Le tronc commun orchestre `load → validate → fetch → diff → apply → report`. ([GitHub][1])
* **Philosophie** : décisions **NOOP / CREATE / UPDATE / SKIP** via une comparaison sur des **formes canoniques** (listes triées, normalisations) ; *toute* plomberie I/O/monitor reste centralisée. ([GitHub][2])

# 2) Contrat Excel (feuille `Alert`) → objet “Desired”

Depuis `core_config.xlsx` (feuille **Alert**, ~59 colonnes), on isole 4 blocs :

1. **Règle cœur** (pour `Create/Edit`)
   `name` (`searchname`), `settings.user` (`owner`), `settings.risk`, `settings.repos`, `settings.aggregate`, `settings.condition.condition_option/value`, `settings.livesearch_data.limit`, fenêtre `timerange_*` (ou conversion depuis `settings.time_range_seconds`), `query` + champs annexes (`description`, `flush_on_trigger`, `search_interval_minute`, `throttling_*`, `metadata`, `log_source`, `alert_context_template`). Ces champs correspondent aux paramètres **documentés** côté API pour la création/édition de règle. ([GitHub][2])

2. **État** (post-création)
   `settings.active` → déclenche **activate/deactivate** après `Create/Edit`. ([GitHub][2])

3. **Partage / RBAC** (post-création)
   `settings.visible_to` (groupes) et `settings.visible_to_users` (utilisateurs) → **share/unshare** sur la règle. ([GitHub][3])

4. **Notifications** (post-création, par type)
   `settings.notifications` (liste d’objets typés `email|syslog|http|sms|snmp|ssh`) → chaque item appelle son **endpoint** dédié (ex. `…/SyslogNotification`). ([GitHub][2])

> Comme pour PP, on **diff** d’abord sur la partie **cœur** (indépendante du node), puis on résout les dépendances par node au **moment apply**. ([GitHub][4])

# 3) `validate(sheets)`

* **Présence**: exiger la feuille `Alert`.
* **Colonnes minimales requises** (en tolérant la casse et alias simples) :
  `name`, `settings.user`, `settings.risk`, `settings.repos`, `settings.aggregate`, `settings.condition.condition_option`, `settings.condition.condition_value`, **au moins un** `settings.livesearch_data.timerange_minute|hour|day` (ou `settings.time_range_seconds` qu’on convertira), `settings.livesearch_data.limit`.
* **Optionnels utiles** : `settings.livesearch_data.query`, `settings.description`, `settings.search_interval_minute`, `settings.flush_on_trigger`, `settings.throttling_*`, `settings.metadata`, `settings.log_source`, `settings.context_template`, `settings.notifications`, `settings.visible_to*`.
* **Colonnes “export only” à ignorer** : tout `…query_info.*`, `settings.version|vid|tid|used_from`, etc.
  Ce schéma suit les “required/optional” du **Create/Edit** et la politique v2 “API whitelist”. ([GitHub][3])

# 4) `iter_desired(sheets)` (normalisation)

* **Normaliser** les cellules (trim, booléens, listes, JSON notifications) selon les conventions v2 (séparateurs `|`/`,` ; sentinelles vides). ([GitHub][2])
* **Produire** un objet “desired” **à 3 niveaux** :
  **`core`** (tous les champs Create/Edit), **`state`** (`active`), **`rbac`** (groupes/users), **`notifications`** (liste d’objets typés).
* **Clé** : `key_fn` = `name` (trim).

# 5) `compare_keys`, `canon_desired`, `canon_existing`

* **Compare uniquement le “cœur”** de la règle pour le **plan** (NOOP/UPDATE) :
  `risk`, `repos` (ensemble normalisé/trié), `aggregate`, `condition_*`, `limit`, `timerange_*` (canoniques), `query`, `description`, `flush_on_trigger`, `search_interval_minute`, `throttling_*`, `metadata` (clé/val triées), `log_source` (triées), `alert_context_template`.
* **Exclure du diff** : `active`, `visible_to*`, **notifications** (gérées en **post-apply**).
* **Canon existing** : re-mapper les champs GET sur la même forme (listes triées, IDs → noms quand pertinent), exactement comme PP où on compare par **noms** en amont et on résout les **IDs** seulement à l’apply. ([GitHub][4])

# 6) `fetch_existing(client, pool, node)`

* **Lister** les règles selon le **scope** (my/shared/vendor/used) déduit de la colonne `tenant_scope`, et construire `{name → existing_obj}`. ([GitHub][2])
* **Précharger caches de dépendances** (par **node**) pour la phase apply :
  **Repos** (clé/ID), **Users/Groups** (owner/assigned_to/share), **Attack tags**, **Log sources**. Ces caches s’appuient sur les **helpers génériques** et les path builders `configapi/monitorapi`. ([GitHub][3])
* **Option** : si l’API expose des détails de règle incluant les notifications/partage, on peut aussi peupler un **snapshot** existant pour faire un diff fin de ces sous-ressources ; sinon, on traitera les notifications/partage en **upsert** idempotent après le cœur.

# 7) `build_payload_create / build_payload_update`

* **Mapper** strictement les **champs documentés** (Create/Edit) et **coercer** les types attendus (minute vs hour/day, booléens `"on"`, tableaux vs CSV si nécessaire), conformément à la politique **API whitelist** du framework. ([GitHub][3])
* **Conversions clés** :

  * `timerange_*` : préférer minute/heure/jour ; convertir depuis `time_range_seconds` si c’est la seule donnée.
  * `flush_on_trigger`, `throttling_enabled`, `notify_*` : booléens → `"on"` (sinon omission).
  * `repos`, `owner`, `assigned_to`, `manageable_by` : **résoudre** en IDs via caches node.
* **Payload Update** : même forme que Create, filtrée aux champs acceptés par PUT.

# 8) `apply(...)` (séquence atomique, idempotente)

1. **CREATE/UPDATE/NOOP** du **cœur** via `DirectorClient` (helpers JSON + monitor). ([GitHub][3])
2. **État actif** : si `desired.state.active` ≠ état courant, appeler `activate`/`deactivate`. ([GitHub][2])
3. **Partage** : construire `rbac_config` depuis `visible_to*` et appeler `share` (ou `unshare` pour vider). ([GitHub][3])
4. **Notifications** : pour chaque item de `notifications`, appeler l’endpoint **par type** (Email, Syslog, HTTP, SMS, SNMP, SSH).

   * Si on a l’existant détaillé : faire un **diff** par type (NOOP/CREATE/UPDATE/DELETE).
   * Sinon : stratégie **upsert** (re-créer/écraser de manière déterministe). ([GitHub][2])
5. **Reporting** : renvoyer `status`, `monitor_ok`, `monitor_branch`, et une **reason** claire en cas de SKIP/FAIL ; c’est le format standard du tronc commun. ([GitHub][1])

# 9) Politique **SKIP** & erreurs (même esprit que PP)

* **SKIP** explicite si une dépendance est manquante sur le node :
  owner/assigned_to inconnu, repo inconnu, groupe/user de partage inconnu, ou champ requis vide ; message lisible pour correction opérateur. (C’est exactement ce que fait PP pour NP/EP/RP manquants.) ([GitHub][4])
* **FAIL** seulement pour erreurs réseau/HTTP bloquantes ; surface le message brut de l’API dans le tableau final (v2). ([GitHub][2])

# 10) Dry-run, idempotence, observabilité

* **Dry-run** : calcule et affiche le **plan** (NOOP/CREATE/UPDATE/SKIP) sans toucher l’API. ([GitHub][1])
* **Idempotence** : un second run sur le même XLSX doit donner 100 % **NOOP** (cœur + sous-ressources). ([GitHub][2])
* **Logs** : niveaux, masquage token, et moniteurs déjà gérés par le tronc commun. ([GitHub][2])

---

## Résumé opérationnel (ce que fait l’import “AlertRules” v2)

* **Diff** uniquement sur le **cœur** de la règle pour décider NOOP/CREATE/UPDATE.
* **Apply** ensuite l’**état** (activate/deactivate), le **partage**, puis les **notifications** (par type), avec résolutions d’IDs **au moment apply** et **SKIP** propre si une dépendance manque. Cette approche réplique le pattern éprouvé de `ProcessingPoliciesImporter`. ([GitHub][4])

Si tu valides cette stratégie, je te rédige la **spec finale** (FR/EN) et j’enchaîne sur l’implémentation quand tu me diras **“GO code”**.

[1]: https://raw.githubusercontent.com/DeDobbeleer/DirectorSync/main/lp_tenant_importer_v2/importers/base.py "raw.githubusercontent.com"
[2]: https://raw.githubusercontent.com/DeDobbeleer/DirectorSync/main/lp_tenant_importer_v2/docs/DirectorSync_v2_Framework_Deep_Dive.md "raw.githubusercontent.com"
[3]: https://raw.githubusercontent.com/DeDobbeleer/DirectorSync/main/lp_tenant_importer_v2/docs/developer_guide_director_sync_v_2_common_trunk.md "raw.githubusercontent.com"
[4]: https://raw.githubusercontent.com/DeDobbeleer/DirectorSync/main/lp_tenant_importer_v2/importers/processing_policies.py "raw.githubusercontent.com"
