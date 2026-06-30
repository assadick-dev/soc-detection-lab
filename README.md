# SOC Detection Lab — Wazuh + Sysmon + MITRE ATT&CK

Laboratoire de détection SOC monté en environnement virtualisé (VirtualBox). Il couvre
l'installation d'un stack Wazuh 4.14, le déploiement d'un agent Windows avec Sysmon,
l'écriture de règles de détection custom alignées MITRE ATT&CK, et une session d'attaques
réelles avec analyse des limites de la détection host-based.

---

## Architecture

| Machine | Rôle | OS |
|---------|------|----|
| SIEM-WAZUH | Manager Wazuh + indexeur + dashboard | Ubuntu (VirtualBox) |
| WIN-VICTIME | Agent Wazuh + Sysmon | Windows 10 (VirtualBox) |

![VirtualBox — VM SIEM-WAZUH](architecture/virtualbox-siem-wazuh.png)
![VirtualBox — VM WIN-VICTIME](architecture/virtualbox-win-victime.png)
![Wazuh dashboard — 1 agent connecté](architecture/wazuh-agent-connecte.png)

Réseau privé hôte VirtualBox (`vboxnet0`) : les deux VMs communiquent sur `192.168.56.0/24`.
La machine hôte Kali joue le rôle de la machine attaquante sur cette même plage.

---

## Contenu du dépôt

| Section | Fichier | Description |
|---------|---------|-------------|
| Installation | [docs/INSTALL.md](docs/INSTALL.md) | Guide pas-à-pas : Wazuh, agent Windows, Sysmon |
| Règles custom | [rules/local_rules.xml](rules/local_rules.xml) | Règles de détection Wazuh alignées MITRE ATT&CK |
| Détection T1059.001 | [detections/T1059.001-powershell-encode/README.md](detections/T1059.001-powershell-encode/README.md) | PowerShell encodé avec pattern offensif |
| Détection T1547.001 | [detections/T1547.001-persistance-run/README.md](detections/T1547.001-persistance-run/README.md) | Persistance via clé Run du registre |
| Tuning | [tuning/README.md](tuning/README.md) | Analyse et suppression des faux positifs connus |
| Phase offensive | [attacks/writeup-attaque-distante.md](attacks/writeup-attaque-distante.md) | Attaques distantes et limites de la détection host-based |
| Script lab | [attacks/lab-attaques.ps1](attacks/lab-attaques.ps1) | Reverse shell PowerShell utilisé lors des tests |

---

## Couverture MITRE ATT&CK

| Technique | Description | Résultat |
|-----------|-------------|---------|
| T1059.001 | PowerShell encodé / `IEX` / `DownloadString` | Détecté — règle 100100 (niveau 13) |
| T1547.001 | Persistance clé Run du registre | Détecté — règle 100102 (niveau 10) |
| T1046 | Scan de ports réseau | Non détecté (limite HIDS — relève d'un NIDS) |
| T1059.001 + T1071 | Reverse shell PowerShell | Bloqué par AMSI avant exécution |
| T1105 | Ingress Tool Transfer (dépôt fichier malveillant) | Alerte Wazuh — règle 92213 (niveau 15) |

---

## Prochaines étapes

- Ajout d'une sonde réseau Suricata (NIDS) pour détecter T1046
- Purple team : contournement AMSI maîtrisé et détection de la tentative
- Simulation T1547.001 et capture de l'alerte
- Dashboard MITRE ATT&CK Navigator (visualisation de la couverture)
