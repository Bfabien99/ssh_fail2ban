#!/bin/bash
###############################################################################
# harden_ssh.sh — Durcissement SSH + fail2ban, portable et idempotent.
#-----------------------------------------------------------------------------
# Applique sur N'IMPORTE QUEL serveur la même config que le VPS DB :
#   1. SSH en authentification par CLÉ uniquement (password + clavier-interactif
#      désactivés, root par clé seulement).
#   2. fail2ban avec une jail sshd (bannit les IP qui abusent), en laissant
#      loopback + Tailscale (100.64.0.0/10) hors de portée des bans.
#
# SÉCURITÉ ANTI-LOCKOUT (le point critique) :
#   Le script REFUSE de désactiver l'authentification par mot de passe s'il ne
#   trouve aucune clé publique exploitable dans les authorized_keys — sinon on
#   se couperait l'accès. Utiliser --force pour passer outre (à vos risques).
#
# Idempotent : relançable sans effet de bord (drop-ins réécrits à l'identique).
# Non destructif : ne touche NI au firewall, NI aux sessions SSH en cours
#   (reload, pas restart). Valide la conf (sshd -t) AVANT de recharger.
#
# Usage :  sudo ./harden_ssh.sh [options]
# Options :
#   --dry-run        Montre ce qui serait fait, n'écrit/installe rien.
#   --force          Désactive le password SSH même sans clé détectée (DANGER).
#   --no-fail2ban    Applique seulement le durcissement SSH.
#   --no-ssh         Installe/configure seulement fail2ban.
#   -h, --help       Cette aide.
###############################################################################

set -euo pipefail

# --- Apparence ---------------------------------------------------------------
if [[ -t 1 ]]; then
	C_OK=$'\033[0;32m'; C_WARN=$'\033[0;33m'; C_ERR=$'\033[0;31m'; C_B=$'\033[1m'; C_0=$'\033[0m'
else
	C_OK=""; C_WARN=""; C_ERR=""; C_B=""; C_0=""
fi
say()  { printf '%s\n' "$*"; }
ok()   { printf '%s✅ %s%s\n' "$C_OK" "$*" "$C_0"; }
warn() { printf '%s⚠️  %s%s\n' "$C_WARN" "$*" "$C_0"; }
die()  { printf '%s❌ %s%s\n' "$C_ERR" "$*" "$C_0" >&2; exit 1; }
hdr()  { printf '\n%s=== %s ===%s\n' "$C_B" "$*" "$C_0"; }

# --- Options -----------------------------------------------------------------
DRY=0; FORCE=0; DO_SSH=1; DO_F2B=1
for a in "$@"; do
	case "$a" in
		--dry-run)     DRY=1 ;;
		--force)       FORCE=1 ;;
		--no-fail2ban) DO_F2B=0 ;;
		--no-ssh)      DO_SSH=0 ;;
		-h|--help)     grep -E '^# ' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		*)             die "Option inconnue : $a (voir --help)" ;;
	esac
done
run() { if [[ "$DRY" -eq 1 ]]; then printf '   [dry-run] %s\n' "$*"; else eval "$@"; fi; }

# --- Pré-requis --------------------------------------------------------------
[[ "$(id -u)" -eq 0 ]] || die "À lancer en root (ou via sudo)."
command -v sshd >/dev/null 2>&1 || die "sshd introuvable — ce n'est pas un serveur SSH ?"

# Nom du service SSH (ssh sur Debian/Ubuntu, sshd sur RHEL/autres).
SSH_UNIT="ssh"
if systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service'; then SSH_UNIT="sshd"; fi

# Détecteur de gestionnaire de paquets (pour fail2ban).
PKG=""
if   command -v apt-get >/dev/null 2>&1; then PKG="apt"
elif command -v dnf     >/dev/null 2>&1; then PKG="dnf"
elif command -v yum     >/dev/null 2>&1; then PKG="yum"
fi

###############################################################################
# 1) DURCISSEMENT SSH
###############################################################################
harden_ssh() {
	hdr "Durcissement SSH (auth par clé uniquement)"

	# --- Garde anti-lockout : au moins une clé publique exploitable ? --------
	local keyfiles=() total=0 f cnt
	for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
		[[ -f "$f" ]] || continue
		cnt=$(grep -vcE '^\s*(#|$)' "$f" 2>/dev/null || echo 0)
		if [[ "$cnt" -gt 0 ]]; then
			keyfiles+=("$f ($cnt)")
			total=$(( total + cnt ))
		fi
	done

	if [[ "$total" -eq 0 ]]; then
		if [[ "$FORCE" -eq 1 ]]; then
			warn "AUCUNE clé trouvée mais --force : on désactive quand même le mot de passe."
			warn "RISQUE DE LOCKOUT — assure-toi d'avoir un accès console de secours."
		else
			die "Aucune clé publique dans les authorized_keys → désactiver le mot de passe
   te couperait l'accès. Ajoute ta clé (ssh-copy-id) puis relance,
   ou --force si tu sais ce que tu fais (accès console requis)."
		fi
	else
		ok "Clés détectées (accès préservé) :"
		printf '     - %s\n' "${keyfiles[@]}"
	fi

	# --- Drop-in de durcissement --------------------------------------------
	local dropdir="/etc/ssh/sshd_config.d" dropfile
	dropfile="$dropdir/10-hardening.conf"
	# S'assurer que le main config inclut bien le répertoire de drop-ins.
	if ! grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config 2>/dev/null; then
		warn "Pas d'Include sshd_config.d → on l'ajoute en tête de /etc/ssh/sshd_config."
		run "sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config"
	fi
	run "mkdir -p '$dropdir'"

	local content="# Durcissement SSH — auth par clé uniquement. Généré par harden_ssh.sh.
# Connexions légitimes attendues 100% publickey. Ne pas éditer à la main.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password"

	if [[ "$DRY" -eq 1 ]]; then
		printf '   [dry-run] écrirait %s :\n' "$dropfile"
		printf '%s\n' "$content" | sed 's/^/        /'
	else
		printf '%s\n' "$content" > "$dropfile"
		chmod 644 "$dropfile"
		ok "Écrit : $dropfile"
	fi

	# --- Validation AVANT reload (zéro coupure si erreur) -------------------
	if [[ "$DRY" -eq 1 ]]; then
		say "   [dry-run] sshd -t (validation) puis 'systemctl reload $SSH_UNIT'"
	else
		if sshd -t; then ok "Syntaxe sshd valide."; else die "sshd -t a échoué — RIEN rechargé, drop-in laissé pour inspection."; fi
		systemctl reload "$SSH_UNIT"
		ok "SSH rechargé (sessions en cours intactes)."
		say "   Effectif : $(sshd -T | grep -E '^passwordauthentication ' )"
	fi
}

###############################################################################
# 2) FAIL2BAN
###############################################################################
setup_fail2ban() {
	hdr "fail2ban (jail sshd)"

	# --- Installation si absent ---------------------------------------------
	if ! command -v fail2ban-client >/dev/null 2>&1; then
		[[ -n "$PKG" ]] || die "fail2ban absent et gestionnaire de paquets non reconnu — installe-le manuellement."
		say "Installation de fail2ban via $PKG…"
		case "$PKG" in
			apt) run "DEBIAN_FRONTEND=noninteractive apt-get update -qq" ; run "DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban" ;;
			dnf) run "dnf install -y epel-release || true" ; run "dnf install -y fail2ban" ;;
			yum) run "yum install -y epel-release || true" ; run "yum install -y fail2ban" ;;
		esac
	else
		ok "fail2ban déjà installé."
	fi

	# --- Binding Python systemd (backend=systemd lit le journal) ------------
	# Indispensable sur les box journald-only (pas de /var/log/auth.log) :
	# sans python3-systemd, le serveur fail2ban crashe au démarrage. C'est un
	# paquet "Recommended" souvent non tiré par l'install de base.
	if ! python3 -c 'import systemd.journal' >/dev/null 2>&1; then
		say "Installation du binding python3-systemd (backend journal)…"
		case "$PKG" in
			apt) run "DEBIAN_FRONTEND=noninteractive apt-get install -y python3-systemd" ;;
			dnf) run "dnf install -y python3-systemd" ;;
			yum) run "yum install -y python3-systemd" ;;
			*)   warn "Gestionnaire de paquets inconnu — installe python3-systemd à la main si backend=systemd." ;;
		esac
	else
		ok "Binding python3-systemd présent."
	fi

	# --- Port(s) SSH réel(s) : repris de la conf sshd effective -------------
	local ssh_ports
	ssh_ports=$(sshd -T 2>/dev/null | awk '/^port /{print $2}' | paste -sd, -)
	[[ -n "$ssh_ports" ]] || ssh_ports="22"

	# --- Backend de ban : on s'ADAPTE à ce qui est présent (rien à installer) -
	# fail2ban a besoin d'un mécanisme pour APPLIQUER les bans. On choisit dans
	# l'ordre nftables -> iptables -> route (blackhole via iproute2, sans aucun
	# pare-feu). On pose un banaction EXPLICITE → comportement déterministe quelle
	# que soit la distro (au lieu de dépendre du défaut packagé). Cohérent avec la
	# promesse du script : on n'installe ni ne modifie aucun pare-feu.
	local banaction=""
	if   command -v nft      >/dev/null 2>&1; then banaction="nftables-multiport"
	elif command -v iptables >/dev/null 2>&1; then banaction="iptables-multiport"
	elif command -v ip       >/dev/null 2>&1; then banaction="route"   # sans pare-feu
	fi
	if [[ -n "$banaction" ]]; then
		ok "Backend de ban : ${banaction}"
		[[ "$banaction" == "route" ]] && warn "Mode 'route' : blackhole de l'IP au niveau routage (ignore le port) — OK pour SSH, mais plus grossier qu'un filtre."
	else
		warn "Ni nft, ni iptables, ni iproute2 → fail2ban DÉTECTERA mais NE BANNIRA PAS."
		warn "Installe nftables (ou iptables) pour rendre les bans effectifs."
	fi

	# --- jail.local (les overrides vont ici, jamais dans jail.conf) ---------
	local jail="/etc/fail2ban/jail.local"
	local content="# Config locale fail2ban — générée par harden_ssh.sh. Ne pas éditer jail.conf.
[DEFAULT]
# Ne jamais bannir loopback ni Tailscale (100.64.0.0/10) → accès de secours.
ignoreip = 127.0.0.1/8 ::1 100.64.0.0/10
${banaction:+# Backend de ban auto-détecté (nftables > iptables > route).
banaction = $banaction
}bantime  = 5h
findtime = 2h
maxretry = 4
backend  = systemd

[sshd]
enabled = true
port    = ${ssh_ports}
# Forcer le backend systemd jusque dans la jail : le [sshd] de jail.conf surcharge
# le backend du [DEFAULT] et retombe sinon sur /var/log/auth.log (absent en
# journald-only) -> 'Have not found any log file for sshd jail' au démarrage.
backend = systemd
# 'aggressive' : attrape aussi scans/échecs publickey, pas seulement password.
mode    = aggressive"

	if [[ "$DRY" -eq 1 ]]; then
		printf '   [dry-run] écrirait %s :\n' "$jail"
		printf '%s\n' "$content" | sed 's/^/        /'
		say "   [dry-run] systemctl enable --now fail2ban + restart"
		return
	fi

	printf '%s\n' "$content" > "$jail"
	chmod 644 "$jail"
	ok "Écrit : $jail (port sshd=${ssh_ports})"
	systemctl enable fail2ban >/dev/null 2>&1 || true
	systemctl restart fail2ban
	sleep 2
	if systemctl is-active --quiet fail2ban; then
		ok "fail2ban actif."
		fail2ban-client status sshd 2>/dev/null | sed 's/^/   /' || true
	else
		warn "fail2ban ne s'est pas activé — vérifie : journalctl -u fail2ban -n50"
	fi
}

###############################################################################
# Exécution
###############################################################################
say "${C_B}harden_ssh.sh${C_0} — service SSH=${SSH_UNIT}, paquets=${PKG:-?}$([[ $DRY -eq 1 ]] && echo ', MODE DRY-RUN')"
[[ "$DO_SSH" -eq 1 ]] && harden_ssh
[[ "$DO_F2B" -eq 1 ]] && setup_fail2ban

hdr "Terminé"
ok "Durcissement appliqué.$([[ $DRY -eq 1 ]] && echo ' (dry-run : rien écrit)')"
cat <<EOF

Rappels :
  • Accès SSH = possession d'une clé privée listée dans authorized_keys,
    depuis n'importe quelle IP (le firewall n'est PAS modifié par ce script).
  • fail2ban n'entrave pas une auth par clé réussie ; il bannit les abus.
  • Pour vérifier :   sshd -T | grep -i password ; fail2ban-client status sshd
EOF
