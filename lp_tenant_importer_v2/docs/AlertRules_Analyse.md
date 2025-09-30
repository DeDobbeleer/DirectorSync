Super — voilà la cartographie **complète** entre la feuille **Alert** de votre `core_config.xlsx` et **tous** les endpoints `AlertRules` pertinents (liste, création, mise à jour, activation, partage, notifications, etc.). Je reste strictement sur l’analyse/mapping — sans code ni considérations “Importers V2”.

---

# 1) Lister les règles (GET list → endpoints `fetch`)

Selon le **périmètre** visé, la liste se fait via différents endpoints “fetch” :

* **Mes règles** → `POST …/AlertRules/MyAlertRules/fetch`
  Filtres utiles : `active` (booléen) ⇢ depuis `settings.active` ; `log_source` (liste) ⇢ depuis `settings.log_source`. ([docs.logpoint.com][1])
* **Règles partagées** → `POST …/AlertRules/SharedAlertRules/fetch`
  Idem filtres `active`, `log_source`. ([docs.logpoint.com][1])
* **Règles “vendor”** → `POST …/AlertRules/VendorAlertRules/fetch`
  Filtre `log_source`. ([docs.logpoint.com][1])
* **Règles “vendor” utilisées** → `POST …/AlertRules/UsedAlertRules/fetch` (+ variante “UsedSharedAlertRules”)
  Filtres `active`, `log_source`. ([docs.logpoint.com][1])

> 🧭 **Astuce de mapping** : utilisez votre champ **`tenant_scope`** (ou équivalent) pour choisir le bon endpoint “fetch” (my/shared/vendor/used).

---

# 2) Créer une règle (POST `/AlertRules`)

Endpoint : `POST …/AlertRules`. Champs principaux côté API et **source dans la feuille** :

* `searchname` (String, **obligatoire**) ⇢ `name` ou `settings.livesearch_data.searchname`. ([docs.logpoint.com][1])
* `risk` (String: `low|medium|high|critical`, **obligatoire**) ⇢ `settings.risk`. ([docs.logpoint.com][1])
* `repos` ([String], **obligatoire**) ⇢ `settings.repos`. ([docs.logpoint.com][1])
* `condition_option` (String: `greaterthan|lessthan|…`, **obligatoire**) ⇢ `settings.condition.condition_option`. ([docs.logpoint.com][1])
* `condition_value` (int, **obligatoire**) ⇢ `settings.condition.condition_value`. ([docs.logpoint.com][1])
* `limit` (int ≥ 1, **obligatoire**) ⇢ `settings.livesearch_data.limit`. ([docs.logpoint.com][1])
* `aggregate` (String: `min|max|avg`, **obligatoire**) ⇢ `settings.aggregate`. ([docs.logpoint.com][1])
* Fenêtre temporelle :
  • `timerange_minute` (ou `timerange_hour`/`timerange_day`) ⇢ `settings.livesearch_data.timerange_minute/hour/day`. Si vous n’avez que `settings.time_range_seconds`, convertissez-le en minutes/heure/jour avant d’affecter. ([docs.logpoint.com][1])
* `query` (String) ⇢ priorité à `settings.livesearch_data.query`; à défaut, concaténer/adapter `settings.extra_config.query` si pertinent. ([docs.logpoint.com][1])
* `description` (String) ⇢ `settings.description`. ([docs.logpoint.com][1])
* `assigned_to` (String userId) ⇢ `settings.assigned_to`. ([docs.logpoint.com][1])
* `owner` (String userId, **obligatoire**) ⇢ `settings.user` (votre colonne “propriétaire”). ([docs.logpoint.com][1])
* `attack_tag` ([String]) ⇢ `settings.attack_tag`. ([docs.logpoint.com][1])
* `log_source` ([String]) ⇢ `settings.log_source`. ([docs.logpoint.com][1])
* `manageable_by` ([String]) ⇢ `settings.visible_to` (groupes RBAC d’incident). ([docs.logpoint.com][1])
* `metadata` ([{field,value}]) ⇢ `settings.metadata` (liste d’objets `{field, value}`). ([docs.logpoint.com][1])
* `alert_context_template` (String – Jinja) ⇢ `settings.context_template`. (Si `settings.is_context_template_enabled` = true, alimentez ce champ.) ([docs.logpoint.com][1])
* `flush_on_trigger` ("on" pour activer) ⇢ `settings.flush_on_trigger` (convertir booléen ⇒ `"on"`/ne pas envoyer). ([docs.logpoint.com][1])
* `search_interval_minute` (int) ⇢ `settings.livesearch_data.search_interval_minute`. ([docs.logpoint.com][1])
* Throttling :
  • `throttling_enabled` ("on") ⇢ `settings.throttling_enabled` (booléen ⇒ `"on"`/absent)
  • `throttling_field` (String) ⇢ `settings.throttling_field`
  • `throttling_time_range` (int, minutes) ⇢ `settings.throttling_time_range` ([docs.logpoint.com][1])
* Autres options : `apply_jinja_template`, `original_data`, `delay_interval_minute` selon vos colonnes (si présentes). ([docs.logpoint.com][1])

> 🔎 **Important** : **`settings.active` ne se poste pas** à la création. L’activation/désactivation passe par deux endpoints dédiés (cf. §4). ([docs.logpoint.com][1])

---

# 3) Mettre à jour (PUT `/AlertRules/{id}`)

Endpoint : `PUT …/AlertRules/{id}` — mêmes champs que “Create” (mêmes conversions), l’**`id`** venant soit de la ligne (si stocké), soit d’une recherche préalable (cf. §1). ([docs.logpoint.com][1])

---

# 4) Activer / Désactiver

* **Activer** : `POST …/AlertRules/{id}/activate`
* **Désactiver** : `POST …/AlertRules/{id}/deactivate`
  Décision en fonction de `settings.active` (true ⇒ appeler *activate*, false ⇒ *deactivate*). ([docs.logpoint.com][1])

---

# 5) Partage / Visibilité

Vos colonnes **`settings.visible_to`** (groupes) et **`settings.visible_to_users`** (utilisateurs) servent à bâtir le **`rbac_config`** de :

* **Partager** : `POST …/AlertRules/{id}/share` → construire `rbac_config` avec soit `group_id` + `group_permission` (READ/EDIT/FULL), soit des `user_permissions` (`user_id`, `permission`).
* **Retirer le partage** : `POST …/AlertRules/{id}/unshare` (aucun paramètre autre que l’id). ([docs.logpoint.com][1])

---

# 6) Notifications (depuis `settings.notifications`)

Votre colonne **`settings.notifications`** contient (généralement) une **liste d’objets** par type (`email`, `syslog`, `http`, `sms`, `snmp`, `ssh` …). Chaque objet alimente **un** endpoint dédié ci-dessous. S’il y a plusieurs notifications de même type, appelez l’endpoint plusieurs fois (une par config).

## 6.1 Email → `POST …/AlertRules/{id}/EmailNotification`

* `notify_email` ("on") ⇢ champ/flag dans l’objet de notif (ou déduit si des emails sont fournis)
* `email_emails` ([String]) ⇢ liste des destinataires
* `subject` (String) ⇢ sujet
* `email_template` (String) ⇢ corps du message
* `email_threshold_option`/`email_threshold_value` ⇢ seuil (minute/hour/day + int)
* `simple_view` (boolean) ⇢ si présent `settings.simple_view` ou dans l’objet notif
* `link_disable` (boolean), `logo_enable` (boolean), `b64_logo` (String base64) ⇢ champs optionnels si votre feuille les fournit
* `dispatch_option` (auto|manual) ⇢ si présent
  👉 **Source** : clés de l’objet `type = "email"` dans `settings.notifications`. ([docs.logpoint.com][1])

## 6.2 Syslog → `POST …/AlertRules/{id}/SyslogNotification`

* `notify_syslog` ("on")
* `server` (String), `port` (int), `protocol` (UDP|TCP)
* `facility` (0–23), `severity` (0–7)
* `message` (String), `split_rows` (boolean)
* Seuil : `threshold_option` (minute|hour|day), `threshold_value` (int)
  👉 **Source** : objet `type = "syslog"` dans `settings.notifications`. ([docs.logpoint.com][1])

## 6.3 HTTP webhook → `POST …/AlertRules/{id}/HTTPNotification`

* `notify_http` ("on"), `protocol` (HTTP|HTTPS)
* `http_url` (String), `http_request_type` (GET|POST|PUT|DELETE|PATCH|HEAD)
* `http_body` (String) — seulement pour POST/PUT/PATCH
* `http_header` (json) → `auth_type` (basic_auth|api_token|bearer_token) + `auth_key`/`auth_value`/`auth_pass` selon le type
* `http_querystring` (String)
* Seuil : `http_threshold_option`/`http_threshold_value`
  👉 **Source** : objet `type = "http"` dans `settings.notifications`. ([docs.logpoint.com][1])

## 6.4 SMS → `POST …/AlertRules/{id}/SMSNotification`

* `notify_sms` ("on")
* `sms_server` (String), `sms_port` (int), `sms_sender` (String), `sms_password` (String)
* `sms_receivers` ([String], 3–15 chiffres), `sms_body` (String)
* Seuil : `sms_threshold_option`/`sms_threshold_value`
  👉 **Source** : objet `type = "sms"` dans `settings.notifications`. ([docs.logpoint.com][1])

## 6.5 SNMP → `POST …/AlertRules/{id}/SNMPNotification`

* `notify_snmp` ("on")
* `snmp_agent` (String) + autres paramètres SNMP (version, communauté, sécurité, OID…) selon votre modèle de notif
  👉 **Source** : objet `type = "snmp"` dans `settings.notifications`. ([docs.logpoint.com][1])

## 6.6 SSH → `POST …/AlertRules/{id}/SSHNotification`

* `notify_ssh` ("on")
* `ssh_server` (String), `ssh_port` (int)
* Authentification : `ssh_auth_type` (password|key) + `ssh_username`, `ssh_auth_password` **ou** clé selon le type
* `ssh_command` (String)
* Seuil : `ssh_threshold_option`/`ssh_threshold_value`
  👉 **Source** : objet `type = "ssh"` dans `settings.notifications`. ([docs.logpoint.com][1])

---

# 7) Propriété, suppression, packaging (si jamais présents dans la feuille)

* **Transférer la propriété** : `POST …/AlertRules/{id}/transferOwnership` avec `userid`. À mapper si vous avez une colonne dédiée (ex. `settings.transfer_to_user`). ([docs.logpoint.com][1])
* **Supprimer** : `DELETE …/AlertRules/{id}` (aucune donnée feuille autre que l’`id`). ([docs.logpoint.com][1])
* **Upload/Install PAK** : endpoints `Upload`, `UploadPublic`, `Install`, `List*Uploads`, `Trash*Uploads` — **non alimentés** par la feuille *Alert* (sauf si vous stockez des noms de fichiers PAK). ([docs.logpoint.com][1])

---

## Récap de correspondance (vue synthétique)

| Domaine (feuille) | Colonne(s)                                                                                               | Endpoint API & champ(s)                                                                     |
| ----------------- | -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Identité          | `name` / `settings.livesearch_data.searchname`                                                           | Create/Edit → `searchname` ([docs.logpoint.com][1])                                         |
| Description       | `settings.description`                                                                                   | Create/Edit → `description` ([docs.logpoint.com][1])                                        |
| Propriétaire      | `settings.user`                                                                                          | Create/Edit → `owner` (obligatoire) ([docs.logpoint.com][1])                                |
| Affectation       | `settings.assigned_to`                                                                                   | Create/Edit → `assigned_to` ([docs.logpoint.com][1])                                        |
| Risque            | `settings.risk`                                                                                          | Create/Edit → `risk` (obligatoire) ([docs.logpoint.com][1])                                 |
| Repos             | `settings.repos`                                                                                         | Create/Edit → `repos` (obligatoire) ([docs.logpoint.com][1])                                |
| Log sources       | `settings.log_source`                                                                                    | Create/Edit → `log_source`; Fetch* → filtre `log_source` ([docs.logpoint.com][1])           |
| Requête           | `settings.livesearch_data.query` (→ principal) ; `settings.extra_config.query` (→ à fusionner si besoin) | Create/Edit → `query` ([docs.logpoint.com][1])                                              |
| Fenêtre           | `settings.livesearch_data.timerange_minute/hour/day` ou `settings.time_range_seconds`                    | Create/Edit → `timerange_*` (convertir si seconds) ([docs.logpoint.com][1])                 |
| Limite            | `settings.livesearch_data.limit`                                                                         | Create/Edit → `limit` (obligatoire) ([docs.logpoint.com][1])                                |
| Condition         | `settings.condition.condition_option/value`                                                              | Create/Edit → `condition_option`, `condition_value` (obligatoires) ([docs.logpoint.com][1]) |
| Agrégat           | `settings.aggregate`                                                                                     | Create/Edit → `aggregate` (obligatoire) ([docs.logpoint.com][1])                            |
| Contexte (Jinja)  | `settings.context_template` (+ `settings.is_context_template_enabled`)                                   | Create/Edit → `alert_context_template` ([docs.logpoint.com][1])                             |
| Throttling        | `settings.throttling_enabled`, `settings.throttling_field`, `settings.throttling_time_range`             | Create/Edit → `throttling_*` (avec `"on"`) ([docs.logpoint.com][1])                         |
| Visibilité        | `settings.visible_to` (groupes), `settings.visible_to_users` (users)                                     | ShareWithUsers → `rbac_config`; UnshareWithUsers (reset) ([docs.logpoint.com][1])           |
| État actif        | `settings.active`                                                                                        | **Activate/Deactivate** (pas dans Create/Edit) ([docs.logpoint.com][1])                     |
| Notifications     | `settings.notifications` (liste d’objets par type)                                                       | Email/Syslog/HTTP/SMS/SNMP/SSH → voir §6 (une requête par objet) ([docs.logpoint.com][1])   |
| Simple view       | `settings.simple_view`                                                                                   | EmailNotification → `simple_view` ([docs.logpoint.com][1])                                  |
| Métadonnées       | `settings.metadata` (liste `{field, value}`)                                                             | Create/Edit → `metadata` ([docs.logpoint.com][1])                                           |

---

## Petites règles de conversion (pratiques)

* Les flags de type **on/off** côté API (`throttling_enabled`, `flush_on_trigger`, `notify_*`) doivent être dérivés de vos booléens (`true` ⇒ `"on"`, `false` ⇒ **omission** ou `"off"` selon préférence). ([docs.logpoint.com][1])
* La **fenêtre temporelle** doit être fournie en `timerange_minute` **ou** `timerange_hour` **ou** `timerange_day` (au moins un). Si vous ne stockez que des secondes, convertissez avant de poster. ([docs.logpoint.com][1])

---

Si vous voulez, je peux maintenant vous produire une **checklist opérationnelle** (par type d’action) ou passer en revue un **exemple concret** d’une ligne de votre feuille pour montrer exactement quels appels seraient faits et avec quelles données — toujours sans code — et ensuite attendre votre “GO” pour la phase de réalisation.

[1]: https://docs.logpoint.com/docs/api-documentation/en/latest/AlertRules.html "AlertRules — API Documentation latest documentation"
