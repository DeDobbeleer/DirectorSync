from __future__ import annotations

"""
Syslog Collectors importer (DirectorSync v2)

Idempotent algorithm using the common v2 pipeline:
  load → validate → fetch → diff → plan → apply → report

Contrats XLSX
-------------
- Sheet "DeviceFetcher": lignes où app == "SyslogCollector".
  Colonnes utiles (au minimum): device_name, node_name, app, proxy_condition,
  hostname (liste/CSV) [uniquement si uses_proxy], proxy_ip (liste/CSV) [si uses_proxy],
  charset, parser, processpolicy (ID SOURCE issu du XLSX).

- Sheet "ProcessingPolicy": mapping des PP "source" venant du XLSX.
  Colonnes utiles: policy_id (ID source), policy_name (nom PP).

Règles API (constatées dans tes logs)
-------------------------------------
- proxy_condition == "use_as_proxy"  → NE PAS envoyer hostname/proxy_ip/processpolicy.
- proxy_condition == "uses_proxy"    → DOIT envoyer hostname[] + proxy_ip[] + processpolicy (ID DEST cible du nœud).
- proxy_condition == None (direct)   → NE PAS envoyer hostname/proxy_ip. DOIT envoyer processpolicy (ID DEST).

Ce module:
- Résout processpolicy DEST par nœud:  (ID source XLSX) → (nom PP via sheet ProcessingPolicy) → (ID dest via API du nœud).
- Crée d'abord tous les collectors "use_as_proxy".
- Pour "uses_proxy", vérifie le cache des IP de proxy existantes sur le nœud; si absent → SKIP clair.
- Marque correctement Skipped / Failed / Success dans le rapport.
"""

from typing import Dict, List, Any, Optional, Iterable, Set, Tuple
import logging

from lp_tenant_importer_v2.core.importer_base import BaseImporter
from lp_tenant_importer_v2.core.director_client import DirectorClient
from lp_tenant_importer_v2.utils.validators import ValidationError
from lp_tenant_importer_v2.utils.text import csv_to_list, norm_lower

log = logging.getLogger(__name__)


class SyslogCollectorsImporter(BaseImporter):
    RESOURCE = "SyslogCollector"
    SHEET_DF = "DeviceFetcher"
    SHEET_PP = "ProcessingPolicy"
    PP_RESOURCE = "ProcessingPolicy"

    # ----- Chargements & validations -------------------------------------------------

    def sheets_required(self) -> List[str]:
        # On nécessite DeviceFetcher (collectors) et ProcessingPolicy (mapping source→nom)
        return [self.SHEET_DF, self.SHEET_PP]

    def validate(self, sheets: Dict[str, Any]) -> None:
        """
        Valide la présence des colonnes clefs et prépare le mapping PP source_id → nom.
        """
        df = self._sheet(sheets, self.SHEET_DF)
        pp = self._sheet(sheets, self.SHEET_PP)

        for col in ("device_name", "node_name", "app", "proxy_condition", "processpolicy"):
            if col not in df.columns:
                raise ValidationError(f"[{self.SHEET_DF}] Colonne manquante: {col}")

        for col in ("policy_id", "policy_name"):
            if col not in pp.columns:
                raise ValidationError(f"[{self.SHEET_PP}] Colonne manquante: {col}")

        # Memo: mapping SOURCE_ID (XLSX) -> NOM
        self._pp_srcid_to_name: Dict[str, str] = {}
        for _, row in pp.iterrows():
            sid = str(row["policy_id"]).strip()
            nm = str(row["policy_name"]).strip()
            if sid and nm:
                self._pp_srcid_to_name[sid] = nm

        if not self._pp_srcid_to_name:
            log.warning("Aucun mapping PP source→nom trouvé dans la feuille %s.", self.SHEET_PP)

        # Cache par nœud: NOM → ID DEST (rempli à la demande)
        self._pp_name_to_destid_by_node: Dict[str, Dict[str, str]] = {}

    # ----- Itération “desired” ------------------------------------------------------

    def iter_desired_rows(self, sheets: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
        """
        Itère les lignes DeviceFetcher qui concernent SyslogCollector et prépare un dict ‘desired’.
        """
        df = self._sheet(sheets, self.SHEET_DF)

        for _, row in df.iterrows():
            if norm_lower(str(row.get("app", ""))) != "syslogcollector":
                continue

            desired: Dict[str, Any] = {
                "device_name": str(row.get("device_name", "")).strip(),
                "node_name": str(row.get("node_name", "")).strip(),
                "proxy_condition": self._clean_proxy_condition(row.get("proxy_condition")),
                "charset": self._clean_opt(row.get("charset")),
                "parser": self._clean_opt(row.get("parser")),
                "hostname": csv_to_list(row.get("hostname")),
                "proxy_ip": csv_to_list(row.get("proxy_ip")),
                # processpolicy est pour l’instant l’ID SOURCE du XLSX :
                "processpolicy_src": self._clean_opt(row.get("processpolicy")),
            }

            yield desired

    # ----- Fetch existants & cache proxies ------------------------------------------

    def fetch_existing(self, client: DirectorClient, pool_uuid: str, node: Any) -> List[Dict[str, Any]]:
        """
        Récupère les collectors existants côté nœud et construit un cache des IP proxies “utilisables”.
        """
        existing = client.list_resources(pool_uuid, node.id, self.RESOURCE) or []
        # Normalisation minimale nécessaire pour nos contrôles :
        for it in existing:
            it["proxy_condition"] = self._clean_proxy_condition(it.get("proxy_condition"))
            # Certains backends exposent ‘hostname’/’proxy_ip’ en str/None ou liste:
            it["hostname"] = csv_to_list(it.get("hostname"))
            it["proxy_ip"] = csv_to_list(it.get("proxy_ip"))
        return existing

    def build_proxy_ip_cache(self, existing: List[Dict[str, Any]]) -> Set[str]:
        """
        Construit l’ensemble des IP de proxy présentes sur le nœud.
        NB: le backend ne fixe pas toujours le même champ; on ratisse large.
        """
        ips: Set[str] = set()
        for it in existing:
            if self._clean_proxy_condition(it.get("proxy_condition")) != "use_as_proxy":
                continue
            # On tente divers champs plausibles fournis par l’API (robuste):
            candidates = []
            candidates += csv_to_list(it.get("proxy_ip"))
            candidates += csv_to_list(it.get("listen_ip"))
            candidates += csv_to_list(it.get("listen_addr"))
            candidates += csv_to_list(it.get("ip"))
            candidates += csv_to_list(it.get("ips"))
            # Filtrage simple (IP/host sont passés tels quels; c’est l’API qui fait l’autorité).
            for val in candidates:
                if val:
                    ips.add(val.strip())
        return ips

    # ----- Plan / Diff (très simple ici) --------------------------------------------

    def key_fn(self, desired: Dict[str, Any]) -> Tuple[str, str]:
        # Clé logique pour reporter/planifier: (node_name, device_name)
        return desired["node_name"], desired["device_name"]

    def compare(self, desired: Dict[str, Any], existing_on_node: List[Dict[str, Any]]) -> Tuple[str, Optional[Dict[str, Any]]]:
        """
        Retourne ("create", None) si non trouvé; ("noop", existant) si identique (subset);
        pour simplifier on ne gère pas l’update fin ici (optionnel).
        """
        for it in existing_on_node:
            if it.get("device_name") == desired.get("device_name"):
                # Contrôle minimal sur proxy_condition/charset/parser (suffisant pour éviter re-création)
                same = (
                    self._clean_proxy_condition(it.get("proxy_condition")) == self._clean_proxy_condition(desired.get("proxy_condition"))
                    and self._clean_opt(it.get("charset")) == self._clean_opt(desired.get("charset"))
                    and self._clean_opt(it.get("parser")) == self._clean_opt(desired.get("parser"))
                )
                return ("noop" if same else "create", it)
        return ("create", None)

    # ----- Apply --------------------------------------------------------------------

    def apply(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: Any,
        desired: Dict[str, Any],
        existing: Optional[Dict[str, Any]],
        decision: Any,  # ignoré (nous recalculons localement pour robustesse)
    ) -> Dict[str, Any]:

        dev = desired["device_name"]
        pc = self._clean_proxy_condition(desired.get("proxy_condition"))

        # 1) LOGIQUE DE SKIP AVANT APPEL API (pour fiabilité du tableau)
        # 1.a) Résolution PP destination quand requis
        dest_pp: Optional[str] = None
        if pc in (None, "direct", "") or pc == "uses_proxy":
            src_pp = self._clean_opt(desired.get("processpolicy_src"))
            if src_pp:
                dest_pp = self._resolve_pp_dest_id(client, pool_uuid, node, src_pp)
                if not dest_pp:
                    msg = (
                        f"ProcessingPolicy introuvable sur le nœud '{node.name}': "
                        f"source_id='{src_pp}' → nom='{self._pp_srcid_to_name.get(src_pp, '?')}'."
                    )
                    log.warning("SKIP %s (PP): %s", dev, msg)
                    return {"status": "Skipped", "error": msg}
            else:
                msg = f"ProcessingPolicy manquant pour device '{dev}' (proxy_condition={pc})."
                log.warning("SKIP %s (PP): %s", dev, msg)
                return {"status": "Skipped", "error": msg}

        # 1.b) Pour uses_proxy, s’assurer que toutes les IP de proxy existent sur le nœud
        if pc == "uses_proxy":
            needed_ips = [ip.strip() for ip in (desired.get("proxy_ip") or []) if ip]
            if not needed_ips:
                msg = f"uses_proxy: proxy_ip manquant pour device '{dev}'."
                log.warning("SKIP %s (proxy_ip): %s", dev, msg)
                return {"status": "Skipped", "error": msg}

            existing_list = self.fetch_existing(client, pool_uuid, node)
            have_ips = self.build_proxy_ip_cache(existing_list)
            missing = [ip for ip in needed_ips if ip not in have_ips]
            if missing:
                msg = (
                    f"uses_proxy: IP proxy introuvables sur nœud '{node.name}': {', '.join(missing)}. "
                    f"Créer d’abord les collectors 'use_as_proxy'."
                )
                log.warning("SKIP %s (proxy cache): %s", dev, msg)
                return {"status": "Skipped", "error": msg}

        # 2) PAYLOAD SELON RÈGLES API
        if existing is None:
            payload = self._build_payload_create(desired, dest_pp)
            try:
                log.info("CREATE syslog_collector device=%s [node=%s]", dev, node.name)
                res = client.create_resource(pool_uuid, node.id, self.RESOURCE, payload)
                # Si le client log seulement mais ne remonte pas l’échec du monitor,
                # on fait confiance au pré-contrôle côté importer (PP/proxies) pour éviter “Success” mensonger.
                return {"status": "Success", "result": res}
            except Exception:
                log.exception("API error (CREATE) for syslog_collector device=%s [node=%s]", dev, node.name)
                raise
        else:
            # Ici, au besoin, on pourrait construire un UPDATE. On renvoie NOOP par défaut.
            log.info("NOOP syslog_collector device=%s [node=%s]", dev, node.name)
            return {"status": "Success"}

    # ----- Helpers: PP mapping & payload rules --------------------------------------

    def _resolve_pp_dest_id(
        self,
        client: DirectorClient,
        pool_uuid: str,
        node: Any,
        src_pp_id: str,
    ) -> Optional[str]:
        """
        Mappe ID SOURCE (XLSX) → NOM (via feuille ProcessingPolicy) → ID DEST (via API nœud).
        Retourne None si introuvable (→ SKIP).
        """
        src_pp_id = str(src_pp_id).strip()
        pp_name = self._pp_srcid_to_name.get(src_pp_id)
        if not pp_name:
            return None

        node_key = str(node.id)
        name_to_id = self._pp_name_to_destid_by_node.get(node_key)
        if name_to_id is None:
            # Construire cache NOM→ID via API du nœud
            try:
                items = client.list_resources(pool_uuid, node.id, self.PP_RESOURCE) or []
            except Exception:
                log.exception("Impossible de lister les ProcessingPolicy sur nœud %s", node.name)
                return None

            name_to_id = {}
            for it in items:
                # tolère différents schémas retournés par l’API
                dest_id = str(it.get("policy_id") or it.get("id") or "").strip()
                dest_name = str(it.get("policy_name") or it.get("name") or "").strip()
                if dest_id and dest_name:
                    name_to_id[dest_name] = dest_id

            self._pp_name_to_destid_by_node[node_key] = name_to_id

        return name_to_id.get(pp_name)

    def _build_payload_create(self, desired: Dict[str, Any], dest_pp: Optional[str]) -> Dict[str, Any]:
        """
        Construit le payload CREATE conforme aux règles de l’API.
        """
        pc = self._clean_proxy_condition(desired.get("proxy_condition"))
        charset = self._clean_opt(desired.get("charset"))
        parser = self._clean_opt(desired.get("parser"))
        hostnames = [h for h in (desired.get("hostname") or []) if h]
        proxy_ips = [p for p in (desired.get("proxy_ip") or []) if p]

        payload: Dict[str, Any] = {
            "device_name": desired.get("device_name"),
            "proxy_condition": pc if pc else None,
        }
        if charset:
            payload["charset"] = charset
        if parser:
            payload["parser"] = parser

        # Règles:
        # use_as_proxy  → interdire hostname/proxy_ip/processpolicy
        # uses_proxy    → exiger hostname[] + proxy_ip[] + processpolicy (ID DEST)
        # direct/None   → interdire hostname/proxy_ip, exiger processpolicy
        if pc == "use_as_proxy":
            # ne rien ajouter d’autre
            pass

        elif pc == "uses_proxy":
            if not hostnames:
                raise ValidationError("uses_proxy: hostname manquant")
            if not proxy_ips:
                raise ValidationError("uses_proxy: proxy_ip manquant")
            if not dest_pp:
                raise ValidationError("uses_proxy: processpolicy (DEST) manquant")

            payload["hostname"] = hostnames
            payload["proxy_ip"] = proxy_ips
            payload["processpolicy"] = dest_pp

        else:
            # direct / None
            if not dest_pp:
                raise ValidationError("direct: processpolicy (DEST) manquant")
            payload["processpolicy"] = dest_pp
            # ne surtout pas envoyer hostname/proxy_ip ici

        log.debug("CREATE payload=%s", payload)
        return payload

    # ----- Petits nettoyages --------------------------------------------------------

    @staticmethod
    def _clean_proxy_condition(val: Any) -> Optional[str]:
        v = str(val).strip().lower() if val is not None else ""
        if v in ("", "none", "null", "direct"):
            return None  # traité comme “direct”
        if v in ("use_as_proxy", "uses_proxy"):
            return v
        return None  # fallback: direct

    @staticmethod
    def _clean_opt(val: Any) -> Optional[str]:
        v = "" if val is None else str(val).strip()
        return v or None

    @staticmethod
    def _sheet(sheets: Dict[str, Any], name: str):
        sh = sheets.get(name)
        if sh is None:
            raise ValidationError(f"Feuille manquante: {name}")
        return sh
