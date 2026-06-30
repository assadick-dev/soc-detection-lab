# Détection T1547.001 — Persistance via clé Run du registre

**Agent :** WIN-VICTIME | **Manager :** SIEM-WAZUH | **Règle custom :** 100102 (niveau 10)

---

## Contexte

T1547.001 : écriture d'une valeur dans `HKCU\...\CurrentVersion\Run` ou
`HKLM\...\CurrentVersion\Run` pour garantir l'exécution d'un payload au démarrage
de la session utilisateur ou du système. C'est l'une des techniques de persistance
les plus simples et les plus répandues.

---

## Commande

```powershell
# Ajout d'une valeur Run depuis PowerShell (simulé)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
  -Name "Backdoor" -Value "C:\Windows\Temp\payload.exe"
```

> Capture à prendre lors de la prochaine simulation.

---

## Détection (règle)

Sysmon Event ID 13 (Registry Value Set) journalise toute écriture dans le registre.
La règle 100102 filtre sur le chemin `\CurrentVersion\Run` :

```xml
<rule id="100102" level="10">
  <if_sid>92052</if_sid>
  <field name="win.eventdata.targetObject" type="pcre2">(?i)\\CurrentVersion\\Run</field>
  <description>Modification d'une clé Run — méthode de persistance fréquente (T1547.001)</description>
  <mitre>
    <id>T1547.001</id>
  </mitre>
</rule>
```

**Niveau 10** → investigation recommandée.

---

## Faux positifs

Les logiciels légitimes utilisent fréquemment les clés Run (antivirus, outils système,
applications utilisateur). Enrichir le contexte avec :

- Le nom et le chemin de l'exécutable pointé par la valeur ajoutée
- L'utilisateur ayant effectué la modification
- La corrélation avec une installation récente connue

---

## Capture

> Capture `capture-alerte-t1547001.png` à prendre lors de la prochaine simulation de
> l'attaque. Commande prévue : `Set-ItemProperty` sur `HKCU:\...\Run`.
