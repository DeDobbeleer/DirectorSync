Bonne question. Avec **auto-py-to-exe** (PyInstaller), voilà comment faire pour que ton `.exe` soit **fiable, auto-contenu et insensible au répertoire courant**.

## 1) Choix de build

* **Recommandé : “One-folder (onedir)”**
  Cela produit `dist/DirectorSync/DirectorSync.exe` + des fichiers à côté. Tu peux alors poser **`.env`**, **`tenants.yml`**, **`resources/profiles.yml`** **dans le même dossier** que l’exe. Simple et robuste.
* “One-file (onefile)”
  L’exe s’extrait dans un répertoire **temporaire** à l’exécution → les chemins relatifs comme `./resources/profiles.yml` deviennent piégeux. Possible, mais demande un peu de code pour retrouver le dossier de l’exe.

## 2) Arbo conseillée (onedir)

```
dist/DirectorSync/
├─ DirectorSync.exe
├─ .env
├─ tenants.yml
├─ resources/
│  └─ profiles.yml
└─ samples/
   └─ core_config.xlsx   (optionnel, pour tester)
```

## 3) Lancer l’exe (avec les mêmes options qu’en dev)

Depuis **PowerShell** (ou CMD) :

```powershell
cd dist/DirectorSync
.\DirectorSync.exe `
  --tenant core `
  --tenants-file .\tenants.yml `
  --xlsx .\samples\core_config.xlsx `
  --dry-run `
  import-repos
```

### Astuce (double-clic)

Crée un **wrapper** `run.cmd` à côté de l’exe pour garantir le bon répertoire de travail :

```bat
@echo off
setlocal
cd /d "%~dp0"
.\DirectorSync.exe --tenant core --tenants-file .\tenants.yml --xlsx .\samples\core_config.xlsx import-repos
pause
```

> Le `cd /d "%~dp0"` force l’exécution **dans le dossier de l’exe**.

## 4) Paramétrage auto-py-to-exe (résumé)

* Script: `lp_tenant_importer_v2/main.py`
* Console based: **Oui**
* Onefile: **Non** (préférer onedir)
* Additional Files (si tu veux embarquer des exemples) : ajouter `samples/`
  *(Pour `.env`, `tenants.yml`, `resources/profiles.yml`, je recommande de les **laisser à côté** de l’exe, pas “embarqués”, pour pouvoir les modifier sans rebuild.)*

## 5) Rendre l’exe autonome vis-à-vis de `.env` et YAML (patch pro, optionnel)

Si tu veux que l’exe retrouve **toujours** `.env` / `tenants.yml` / `profiles.yml` **à côté de l’exe** (même en onefile), ajoute ce petit durcissement (EN only) :

### `core/config.py` — chercher la configuration **au dossier de l’exe**

```python
# at top
import sys
from pathlib import Path

def _exe_dir() -> Path:
    # When frozen by PyInstaller, sys.executable points to the .exe
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    # Dev mode: fall back to CWD (keeps current behavior)
    return Path.cwd()
```

Dans `Config.from_env()` (avant `find_dotenv`), ajoute :

```python
# 1) Load .env next to the executable, if present
exe_env = _exe_dir() / ".env"
if exe_env.is_file():
    load_dotenv(exe_env, override=False)

# 2) Then load .env in current working dir (keeps dev experience)
env_path = find_dotenv(usecwd=True) or ""
load_dotenv(env_path, override=False)
```

Toujours dans `from_env()`, si `LP_TENANTS_FILE` **manque**, applique une valeur par défaut **relative à l’exe** :

```python
tenants_file = os.getenv("LP_TENANTS_FILE")
if not tenants_file:
    default_tenants = _exe_dir() / "tenants.yml"
    if default_tenants.is_file():
        tenants_file = str(default_tenants)
```

Et pour `LP_PROFILE_FILE` (si tu l’utilises), même logique avec `resources/profiles.yml`.

> Résultat : tu peux **déposer l’exe + `.env` + `tenants.yml` + `resources/profiles.yml` au même endroit**, et l’exe les trouvera tout seul, quel que soit le répertoire depuis lequel l’utilisateur le lance.

## 6) Pièges courants & réponses pro

* **“File not found” pour l’XLSX** : fournis un **chemin relatif à l’exe** (via `run.cmd`) ou un chemin **absolu**.
* **Double-clic sans arguments** : c’est un **CLI** ; passer par un script `.cmd` ou un **raccourci** avec les arguments.
* **Certificat TLS** en lab : tu as `--no-verify` si besoin.
* **Logs** : ils s’affichent en console ; si tu veux en plus un fichier, on peut ajouter un `FileHandler` vers `logs/` à côté de l’exe.

Si tu veux, je te prépare un **petit zip “dist modèle”** avec `DirectorSync.exe` factice + `run.cmd` + `.env`/`tenants.yml`/`resources/` — pour que tu voies exactement quoi livrer à un client Windows.
