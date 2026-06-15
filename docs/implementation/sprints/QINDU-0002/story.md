# QINDU-0002: Installer Windows + Service

**Status**: IN_PROGRESS
**Phase**: 2 - Installation & Packaging
**Sprint**: QINDU-0002
**Dependency**: QINDU-0001 ✅ DONE (122 tests, proxy TLS, service handler, CA génération)

## Résumé

Produire un installateur MSI (WiX Toolset) qui déploie l'agent Qindu comme service Windows, installe la CA racine dans le trust store machine, configure les policies Chrome/Edge (PAC + QUIC), pose les règles firewall loopback, et nettoie tout à la désinstallation — avec un dialogue explicite pour la suppression du vault et des logs. Un seul binaire `agent.exe`, pas de helper Go custom. CI : build MSI sur `windows-latest` déclenché par tags de release.

## Scope

### Inclus

1. **Projet WiX Toolset** (`installer/wix/`) :
   - `qindu.wxs` principal + `includes/*.wxs` modulaires + `locale/en-us.wxl`
   - `UpgradeCode` fixe, `ProductCode` / `PackageCode` auto-générés
   - Upgrade supporté, downgrade bloqué (`AllowDowngrades="no"`)
2. **Déploiement des fichiers** :
   - `%PROGRAMFILES%\Qindu\agent.exe` (binaire unique cross-compilé)
   - `%PROGRAMFILES%\Qindu\configs\default.yaml` (overwrite à l'upgrade uniquement)
   - `%PROGRAMDATA%\Qindu\` créé avec ACL : SYSTEM + Administrateurs + LocalService uniquement
3. **Génération et installation de la CA** :
   - WiX CustomAction appelle `"%PROGRAMFILES%\Qindu\agent.exe" ca-init`
   - `ca-init` lit `configs/default.yaml` (providers) pour les Name Constraints
   - Optionnel : `--unsafe` via checkbox MSI (`UNSAFE_CA=1`)
   - `ca-init` détruit et remplace toute CA existante
   - WiX CustomAction appelle `certutil -addstore Root "%PROGRAMDATA%\Qindu\ca.crt"`
4. **Service Windows** :
   - Nom : `QinduAgent`, compte : `NT AUTHORITY\LocalService`
   - `sc create` ou WiX `<ServiceInstall>` natif
   - Démarrage automatique après installation
   - Arrêt avant désinstallation/upgrade
5. **Configuration navigateur (Registry GPO)** :
   - Bloc Chrome : `HKLM\Software\Policies\Google\Chrome\`
     - `ProxyMode` = `"pac_script"` (REG_SZ)
     - `ProxyPacUrl` = `"http://127.0.0.1:8787/proxy.pac"` (REG_SZ)
   - Bloc Chrome QUIC : `HKLM\Software\Policies\Google\Chrome\QuicAllowed` = `0` (REG_DWORD)
   - Bloc Edge : `HKLM\Software\Policies\Microsoft\Edge\`
     - `ProxyMode` = `"pac_script"` (REG_SZ)
     - `ProxyPacUrl` = `"http://127.0.0.1:8787/proxy.pac"` (REG_SZ)
   - Bloc Edge QUIC : `HKLM\Software\Policies\Microsoft\Edge\QuicAllowed` = `0` (REG_DWORD)
   - Écriture systématique, pas de détection de navigateur installé
6. **Règles firewall** :
   - CustomAction `netsh advfirewall` :
     - Allow loopback : `remoteip=127.0.0.1,::1 localport=8787 protocol=TCP action=allow dir=in`
     - Block external : `remoteip=any localport=8787 protocol=TCP action=block dir=in`
7. **Désinstallation** :
   - Arrêt + suppression du service
   - Suppression de la CA du trust store : `certutil -delstore Root "Qindu AI Privacy CA"`
   - Suppression des clés registry Chrome/Edge
   - Suppression des règles firewall
   - Suppression des fichiers installés (`%PROGRAMFILES%\Qindu\`)
   - Dialogue WiX : checkbox "Delete all Qindu data (vault, logs)" → si coché, `RemoveFolderEx %PROGRAMDATA%\Qindu\`
   - Si décoché, dossier `%PROGRAMDATA%\Qindu\` orphelin conservé
8. **Résolution des chemins dans l'agent** (mise à jour `cmd/agent/main.go`) :
   - `--config <path>` flag CLI (prioritaire)
   - `QINDU_CONFIG` env var
   - `C:\Program Files\Qindu\configs\default.yaml` (Windows service)
   - `./configs/default.yaml` (relatif exécutable, fallback dev)
   - `%PROGRAMDATA%\Qindu\` pour CA key, cert, logs, vault (futur)
   - Override : `%PROGRAMDATA%\Qindu\config.yaml` merge shallow par-dessus `default.yaml`
9. **Sous-commande `ca-init`** dans `cmd/agent/main.go` :
   - `agent.exe ca-init` : génère CA avec Name Constraints (depuis providers YAML)
   - `agent.exe ca-init --unsafe` : bannière avertissement interactive + confirmation + CA sans constraints
   - `agent.exe ca-init --config <path>` : override config path
   - Détruit/replace toute CA existante
   - Réutilise `internal/tls/ca.go` (CreateOrLoadCA, SaveCA, LoadCA)
10. **CI GitHub Actions** :
    - Job existant `ubuntu-latest` : inchangé (vet, test, cross-compile)
    - Nouveau job `windows-latest` : build MSI via WiX Toolset
    - Déclencheur : `workflow_dispatch` OU push de tag `v*`
    - Produit `Qindu-Installer-x64.msi` en artifact
11. **Tests** :
    - Compilation de `agent.exe ca-init` vérifiée (Windows + cross-compile Linux)
    - Les fichiers `.wxs` validés syntaxiquement (WiX `candle -nologo` en dry-run)
    - Tests unitaires pour la sous-commande `ca-init` (génération CA, Name Constraints parsing, flags `--unsafe`, `--config`)
    - Pas de tests d'intégration MSI en CI (nécessite Windows interactif)

### Exclu (futurs sprints)

- ❌ Détection PII / tokenisation / vault (QINDU-0005+)
- ❌ Provider adapters (ChatGPT, Claude)
- ❌ Désinstallation custom hors MSI (tout est dans le MSI maintenant)
- ❌ Firefox, autres navigateurs
- ❌ Signature Authenticode EV/OV (self-sign ou org-sign en release manuelle)
- ❌ Tray icon, UI locale
- ❌ Page d'erreur fail-closed
- ❌ Hot-reload config

## Architecture cible pour ce sprint

```
Qindu repo
  │
  ├── cmd/agent/main.go          ← Ajout sous-commande "ca-init" + résolution chemins
  ├── internal/tls/ca.go         ← Existant (CreateOrLoadCA), réutilisé par ca-init
  │
  └── installer/
        ├── wix/
        │   ├── qindu.wxs            # Point d'entrée WiX
        │   ├── includes/
        │   │   ├── files.wxs        # Composants fichiers (agent.exe, config)
        │   │   ├── service.wxs      # Service Windows QinduAgent
        │   │   ├── registry-chrome.wxs  # Policies Chrome (proxy + QUIC)
        │   │   ├── registry-edge.wxs    # Policies Edge (proxy + QUIC)
        │   │   ├── firewall.wxs     # Règles firewall netsh
        │   │   ├── ca-trust.wxs     # CustomAction agent.exe ca-init + certutil
        │   │   ├── cleanup.wxs      # CustomAction désinstallation RemoveFolderEx
        │   │   └── dialogs.wxs      # Dialogues (checkbox uninstall, unsafe CA)
        │   └── locale/
        │       └── en-us.wxl        # Strings anglais
        └── README.md               # Instructions build MSI
```

## ADRs applicables

| ADR | Titre | Pertinence |
|-----|-------|-----------|
| ADR-003 | Stratégie TLS (CA unique, certs lazy, SAN wildcard) | CA génération, trust store, Name Constraints |
| ADR-006 | Service Windows (binaire unique, auto-détection) | Déploiement service, LocalService, graceful shutdown |
| ADR-010 | Validation TLS upstream (trust store, compatibilité) | Compatibilité proxies entreprise |

### ADR-003 mise à jour

Le sprint ajoute les **Name Constraints** à la CA racine :
- `ca-init` normal : permitted DNS subtrees pour chaque `*.domaine` des providers YAML
- `ca-init --unsafe` : pas de constraints (pour compatibilité si Chrome/Edge ne les respectent pas)

## Critères d'acceptation

1. **Build MSI** : `candle qindu.wxs && light qindu.wixobj` produit `Qindu-Installer-x64.msi`
2. **Installation fresh** : `msiexec /i Qindu-Installer-x64.msi` installe agent.exe + config + génère CA + trust store + crée service + écrit registry + pose firewall
3. **Service en cours** : `sc query QinduAgent` → RUNNING. `curl http://127.0.0.1:8787/health` → `{"status":"up"}`
4. **Policies actives** : `chrome://policy` affiche ProxyMode=pac_script, ProxyPacUrl, QuicAllowed=0
5. **Firewall** : `netsh advfirewall firewall show rule name="Qindu Agent (Allow Loopback)"` → confirmé actif
6. **Trust store** : `certlm.msc` → Autorités de certification racines → "Qindu AI Privacy CA" présent
7. **Name Constraints** (mode normal) : Le certificat CA contient l'extension Name Constraints avec `*.chatgpt.com`, `*.claude.ai`
8. **Upgrade** : Nouvelle version écrase default.yaml, préserve `%PROGRAMDATA%`, remplace la CA, redémarre le service
9. **Désinstallation avec suppression données** : `msiexec /x ... DELETEDATA=1` → plus de fichiers, plus de service, plus de CA, plus de registry, `%PROGRAMDATA%\Qindu\` supprimé
10. **Désinstallation sans suppression données** : `msiexec /x ...` (sans cocher) → `%PROGRAMDATA%\Qindu\` conservé
11. **Mode unsafe** : Installation avec checkbox → CA sans Name Constraints → navigateur fonctionne
12. **CLI ca-init** : `agent.exe ca-init --config other.yaml` génère CA avec les providers de other.yaml
13. **Override config** : Fichier `%PROGRAMDATA%\Qindu\config.yaml` merge shallow sur `default.yaml`
14. **CI Windows** : Job `windows-latest` build le MSI sur push de tag `v*`, publie l'artifact
15. **Cross-compile Linux** : `GOOS=windows GOARCH=amd64 go build ./cmd/agent/` compile (sans Windows APIs)

## Contraintes de sécurité

- La clé privée CA n'est **jamais** loggée par `ca-init` ou l'installateur
- Les règles firewall bloquent explicitement toute connexion non-loopback sur le port 8787
- Le service tourne sous `LocalService` (pas SYSTEM)
- Les ACLs `%PROGRAMDATA%\Qindu\` excluent `Authenticated Users`
- `ca-init --unsafe` affiche une bannière d'avertissement en anglais et demande confirmation interactive (stdin)
- Les policies navigateur sont en HKLM (machine-wide), pas HKCU
- La désinstallation supprime toutes les traces si l'utilisateur le demande
- `InsecureSkipVerify` reste désactivé par défaut (pas de régression)
- Aucune PII dans les logs du custom action WiX ou de `ca-init`

## Configuration de référence

```yaml
# configs/default.yaml (inchangé depuis QINDU-0001)
agent:
  listen_addr: "127.0.0.1"
  listen_port: 8787
  mode: "enforce"
  fail_mode: "fail_open"

tls:
  ca_name: "Qindu AI Privacy CA"
  ca_validity_years: 10
  ca_key_algorithm: "ECDSA_P256"
  cert_cache_enabled: true
  upstream_validation: "system"

providers:
  chatgpt:
    enabled: true
    domains:
      - "chatgpt.com"
  claude:
    enabled: true
    domains:
      - "claude.ai"

logging:
  level: "info"
  format: "json"
  pii_logging: false
```

Le fichier override optionnel (`%PROGRAMDATA%\Qindu\config.yaml`) peut contenir n'importe quel sous-ensemble de clés qui écraseront celles du `default.yaml` (merge shallow).

## Notes pour l'implémentation

### Priorité des chemins (agent.go)
```
1. --config <path> flag
2. QINDU_CONFIG env var
3. filepath.Join(os.Getenv("PROGRAMFILES"), "Qindu", "configs", "default.yaml")  // Windows
4. filepath.Join(filepath.Dir(os.Executable()), "configs", "default.yaml")       // fallback
```

### Sous-commande ca-init
```go
// cmd/agent/main.go
func runCAInit(args []string) error {
    unsafe := slices.Contains(args, "--unsafe")
    configPath := extractConfigPath(args)  // --config <path> ou default
    
    cfg := loadConfig(configPath)
    ca := generateCA(cfg.TLS)
    
    if !unsafe {
        addNameConstraints(ca, cfg.Providers)  // *.chatgpt.com, *.claude.ai
    }
    
    saveCA(ca)  // DPAPI sur Windows, mémoire sur autre OS
    return nil
}
```

### Structure WiX
- `qindu.wxs` : `<Product>`, `<Package>`, `<MajorUpgrade>`, `<?include?>` de tous les includes
- `includes/files.wxs` : `<Directory>`, `<Component>` pour chaque fichier
- `includes/service.wxs` : `<ServiceInstall>`, `<ServiceControl>`
- `includes/registry-chrome.wxs` : `<RegistryKey>` + `<RegistryValue>`
- `includes/registry-edge.wxs` : idem
- `includes/firewall.wxs` : `<CustomAction ExeCommand='netsh advfirewall...'>`
- `includes/ca-trust.wxs` : `<CustomAction ExeCommand='agent.exe ca-init'>` + `certutil`
- `includes/cleanup.wxs` : `<CustomAction ExeCommand='certutil -delstore'>` + `RemoveFolderEx`
- `includes/dialogs.wxs` : `<Dialog>` avec `<Checkbox Property="UNSAFE_CA">`, `<Checkbox Property="DELETEDATA">`

### CI Windows runner
```yaml
build-msi:
  runs-on: windows-latest
  if: startsWith(github.ref, 'refs/tags/v') || github.event_name == 'workflow_dispatch'
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-go@v5
      with: { go-version: '1.26' }
    - run: go build -o agent.exe ./cmd/agent/
    - run: choco install wixtoolset -y
    - run: cd installer/wix && candle qindu.wxs && light qindu.wixobj
    - uses: actions/upload-artifact@v4
      with: { name: Qindu-Installer-x64.msi, path: installer/wix/Qindu-Installer-x64.msi }
```

## Dépendances Go prévues

Aucune nouvelle dépendance Go. `ca-init` réutilise les packages existants :
- `internal/tls/` (CA generation)
- `internal/policy/` (YAML config parsing + providers)
- `crypto/x509` (Name Constraints via `PermittedDNSDomains`)
- `gopkg.in/yaml.v3` (config parsing, déjà présent)
