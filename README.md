# ssh_fail2ban

Durcissement SSH + fail2ban réutilisable, en un seul script idempotent.
À déposer sur n'importe quel serveur et lancer — applique la même politique
partout : **SSH par clé uniquement** + **fail2ban** qui bannit les IP abusives.

## Ce que le script applique

1. **SSH — authentification par clé seulement**
   (`/etc/ssh/sshd_config.d/10-hardening.conf`)
   ```
   PasswordAuthentication no
   KbdInteractiveAuthentication no
   PermitRootLogin prohibit-password
   ```
   → annule le brute-force par mot de passe. Tu continues à te connecter par clé,
   depuis n'importe quelle IP.

2. **fail2ban — jail `sshd`** (`/etc/fail2ban/jail.local`)
   ```
   maxretry=4  findtime=10m  bantime=5h  mode=aggressive
   ignoreip = 127.0.0.1/8 ::1 100.64.0.0/10   # loopback + Tailscale jamais bannis
   ```

## Backend de ban auto-détecté (rien à installer)

fail2ban a besoin d'un mécanisme pour *appliquer* les bans. Le script le détecte
et pose un `banaction` **explicite** (comportement déterministe, peu importe la
distro), dans cet ordre :

| Présent sur la machine | `banaction` choisi   | Remarque                                   |
|------------------------|----------------------|--------------------------------------------|
| `nft` (nftables)       | `nftables-multiport` | Préféré (pare-feu moderne)                 |
| sinon `iptables`       | `iptables-multiport` | Repli classique                            |
| sinon `ip` (iproute2)  | `route`              | **Sans pare-feu** : blackhole l'IP (route) |
| aucun des trois        | *(aucun)*            | Avertissement : détection seule, pas de ban |

Le script **n'installe ni ne modifie aucun pare-feu** : il s'adapte à l'existant.
Le mode `route` bannit au niveau routage (ignore le port) — suffisant pour stopper
un brute-force SSH, mais plus grossier qu'un filtre par port.

## Sécurité anti-lockout

Le script **refuse** de désactiver le mot de passe s'il ne trouve **aucune clé
publique** dans les `authorized_keys` (root + tous les `/home/*`). Sans clé,
couper le mot de passe = se verrouiller dehors. Mets ta clé d'abord
(`ssh-copy-id`), puis relance. `--force` passe outre (accès console requis).

Le script ne **redémarre pas** SSH (il fait `reload` après `sshd -t`) :
**les sessions en cours ne sont jamais coupées**, et une conf invalide n'est
jamais rechargée.

## Usage

```bash
sudo ./harden_ssh.sh              # applique tout (SSH + fail2ban)
sudo ./harden_ssh.sh --dry-run    # montre ce qui serait fait, n'écrit rien
sudo ./harden_ssh.sh --no-fail2ban  # durcissement SSH seul
sudo ./harden_ssh.sh --no-ssh       # fail2ban seul
sudo ./harden_ssh.sh --force        # désactive le password même sans clé (DANGER)
```

Déploiement sur un serveur distant :
```bash
scp harden_ssh.sh root@serveur:/tmp/ && ssh root@serveur 'bash /tmp/harden_ssh.sh'
```

## Portabilité

- Service SSH détecté automatiquement (`ssh` Debian/Ubuntu, `sshd` RHEL…).
- fail2ban installé via `apt`, `dnf` ou `yum` selon la distro (EPEL ajouté sur RHEL).
- Port SSH repris de la conf effective (`sshd -T`), même si non standard.

## Ce que le script NE fait PAS (volontaire)

- **Il ne touche pas au firewall** (ufw/nftables). L'ouverture du port SSH et la
  politique réseau restent sous ton contrôle. Vérifie que ton port SSH est bien
  autorisé avant de compter dessus.
- Il ne supprime aucune clé existante.

## Vérifier après coup

```bash
sshd -T | grep -iE 'passwordauthentication|permitrootlogin'
fail2ban-client status sshd
```

## Aide-mémoire fail2ban

### État / inspection
```bash
fail2ban-client status                 # liste des jails actives
fail2ban-client status sshd            # détail jail sshd : IP bannies, compteurs
fail2ban-client banned                 # toutes les IP bannies, toutes jails
systemctl status fail2ban              # service up/down
journalctl -u fail2ban -n 50 --no-pager   # logs (diagnostic démarrage)
```

### Débloquer une IP (unban)
```bash
fail2ban-client set sshd unbanip 1.2.3.4    # retire le ban d'une IP
fail2ban-client unban 1.2.3.4               # retire l'IP de TOUTES les jails
fail2ban-client unban --all                 # vide TOUS les bans (toutes jails)
```

### Bloquer une IP manuellement (ban)
```bash
fail2ban-client set sshd banip 1.2.3.4      # bannit tout de suite via la jail
```

### Ne jamais bannir une IP (whitelist permanente)
À mettre dans `ignoreip` de `/etc/fail2ban/jail.local` (séparées par des espaces),
puis recharger. Loopback et Tailscale (`100.64.0.0/10`) y sont déjà.
```bash
# éditer jail.local -> ignoreip = 127.0.0.1/8 ::1 100.64.0.0/10 1.2.3.4
fail2ban-client reload sshd            # recharge sans tout couper
# (ou : fail2ban-client set sshd addignoreip 1.2.3.4  -> non persistant, perdu au restart)
```

### Voir / gérer les règles
```bash
fail2ban-client get sshd bantime       # durée de ban courante
fail2ban-client get sshd findtime      # fenêtre de détection
fail2ban-client get sshd maxretry      # seuil d'échecs avant ban
fail2ban-client get sshd ignoreip      # IP/plages jamais bannies
iptables -L -n | grep -i f2b           # règles iptables posées par fail2ban
nft list ruleset | grep -A20 f2b       # idem si nftables
```

### Recharger après modif de config
```bash
fail2ban-client reload                 # recharge tout (préserve les bans actifs)
fail2ban-client reload sshd            # recharge la seule jail sshd
```

> **Si tu te bannis toi-même** : reconnecte-toi via l'IP **Tailscale** (jamais bannie),
> puis `fail2ban-client set sshd unbanip <ton_ip>`.
