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
   maxretry=4  findtime=10m  bantime=1h  mode=aggressive
   ignoreip = 127.0.0.1/8 ::1 100.64.0.0/10   # loopback + Tailscale jamais bannis
   ```

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
