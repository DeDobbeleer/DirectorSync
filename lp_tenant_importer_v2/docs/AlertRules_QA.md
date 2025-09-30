Voici la **version courte** demandée.

**1) Combien d’éléments “Alerte” à prendre en compte (pour un import complet) ?**
👉 **10** éléments fonctionnels :

1. Règle d’alerte (AlertRule, définition)
2. État actif/inactif (Activate/Deactivate) ([Logpoint Docs][1])
   3–8. Notifications par type (Email, Syslog, HTTP, SMS, SNMP, SSH) ([Logpoint Docs][1])
3. Partage/RBAC (Share/Unshare) ([Logpoint Docs][1])
4. Transfert de propriété (TransferOwnership) ([Logpoint Docs][1])

**2) Combien de types d’endpoints à utiliser ?**
👉 **18** au total (import complet) :

* Core: Create, Edit, Activate, Deactivate (4) ([Logpoint Docs][1])
* Listing: FetchMy, FetchShared, FetchVendor, FetchUsed, FetchUsedShared (5) ([Logpoint Docs][1])
* Partage & propriété: ShareWithUsers, UnshareWithUsers, TransferOwnership (3) ([Logpoint Docs][1])
* Notifications: Email, Syslog, HTTP, SMS, SNMP, SSH (6) ([Logpoint Docs][1])

**3) Prérequis / dépendances externes aux AlertRules**

* **Repos** existants (IDs valides) — requis par Create. ([Logpoint Docs][1])
* **Owner/Assigned_to** (IDs utilisateurs), **groupes** pour `manageable_by` / partage. ([Logpoint Docs][1])
* **Attack tags** (IDs via MitreAttacks – FetchMitreAttacks). ([Logpoint Docs][1])
* **Log sources** (si utilisées). ([Logpoint Docs][1])
* **Paramètres système**: `delay_interval_minute` nécessite `timestamp_on=log_ts` (SystemSettingsGeneral). ([Logpoint Docs][1])
* **Cibles de notifications** accessibles (serveur syslog, URL webhook HTTP, passerelle SMS, agent SNMP, hôte SSH, etc.).

**4) Champs requis (Create)**
`searchname`, `owner`, `risk`, `repos`, `aggregate`, `condition_option`, `condition_value`, `limit`, et **une** fenêtre `timerange_minute` **ou** (`timerange_hour`/`timerange_day`). `query` est recommandé mais optionnel. ([Logpoint Docs][1])

**5) Liste des champs “complexes” à parser/typer (JSON de référence, pour NOOP/CREATE/UPDATE)**

```json
{
  "alert_core_required": [
    "searchname", "owner", "risk", "repos",
    "aggregate", "condition_option", "condition_value",
    "limit", "timerange_minute|hour|day"
  ],
  "alert_core_optional": [
    "query", "description", "assigned_to", "log_source",
    "manageable_by", "metadata[{field,value}]",
    "alert_context_template", "flush_on_trigger",
    "search_interval_minute", "throttling_enabled",
    "throttling_field", "throttling_time_range",
    "original_data"
  ],
  "state": ["active"], 
  "sharing_rbac": {
    "groups": [{"group_id": "...", "permission": "READ|EDIT|FULL"}],
    "users": [{"user_id": "...", "permission": "READ|EDIT|FULL"}]
  },
  "notifications": {
    "email": {
      "notify_email": true,
      "email_emails": ["user@ex.com"],
      "subject": "...",
      "email_template": "...",
      "email_threshold_option": "minute|hour|day",
      "email_threshold_value": 0,
      "simple_view": false,
      "dispatch_option": "auto|manual",
      "logo_enable": false,
      "b64_logo": null,
      "link_disable": false
    },
    "syslog": {
      "notify_syslog": true,
      "server": "host", "port": 514, "protocol": "UDP|TCP",
      "facility": 13, "severity": 5,
      "message": "...", "split_rows": false,
      "threshold_option": "minute|hour|day",
      "threshold_value": 0,
      "dispatch_option": "auto|manual"
    },
    "http": {
      "notify_http": true,
      "http_url": "https://...", "http_request_type": "GET|POST|PUT|DELETE|PATCH|HEAD",
      "http_body": "...",
      "http_header": {
        "auth_type": "basic_auth|api_token|bearer_token",
        "auth_key": "...", "auth_value": "...", "auth_pass": "..."
      },
      "http_querystring": "",
      "http_threshold_option": "minute|hour|day",
      "http_threshold_value": 0,
      "dispatch_option": "auto|manual"
    },
    "sms": {
      "notify_sms": true,
      "sms_server": "host", "sms_port": 25,
      "sms_sender": "name", "sms_password": "secret",
      "sms_receivers": ["+33123456789"],
      "sms_body": "...",
      "sms_threshold_option": "minute|hour|day",
      "sms_threshold_value": 0,
      "dispatch_option": "auto|manual"
    },
    "snmp": {
      "notify_snmp": true,
      "snmp_agent": "host",
      "snmp_version": "v2c|v3",
      "snmp_security": { "community": "public", "user": "...", "auth": "...", "priv": "..." }
    },
    "ssh": {
      "notify_ssh": true,
      "ssh_server": "host", "ssh_port": 22,
      "ssh_auth_type": "password|key",
      "ssh_username": "user",
      "ssh_auth_password": "secret",
      "ssh_key": "PEM...",
      "ssh_command": "..."
    }
  }
}
```

*Réfs API principales : champs “Create/Edit”, fenêtres temporelles, throttling, métadonnées, et liste complète des endpoints (Create/Edit/Activate/Deactivate/Fetch*, Notifications, Share/Unshare, TransferOwnership) sont documentés sur la page **AlertRules 2.8.0**.* ([Logpoint Docs][1])

[1]: https://docs.logpoint.com/docs/api-documentation/en/latest/AlertRules.html "AlertRules — API Documentation latest documentation"
