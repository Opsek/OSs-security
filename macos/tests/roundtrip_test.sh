#!/usr/bin/env bash
# ==============================================================================
# OPSEK restore round-trip test
#
# Proves the restore promise without touching the real machine: it sources the
# REAL snapshot_system_state and the REAL generated rollback from utils/backup.sh,
# with every system command replaced by a shell-function stub backed by an
# in-memory STATE array. The test asserts that capture -> harden -> rollback
# returns every toggle to its exact pre-Apply value.
#
# This is the gate that stops restore fidelity from eroding silently: when you
# add a toggle to snapshot_system_state, add it to the INIT/harden/assert lists
# here so a missing revert fails the test instead of shipping.
#
# Run: bash macos/tests/roundtrip_test.sh   (or via macos/tests/run.sh)
# ==============================================================================

# Repo root derived from this file, never hardcoded.
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; FAIL=0
ok(){ echo "  PASS: $1"; PASS=$((PASS+1)); }
no(){ echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

# ---- Simulated system state -------------------------------------------------
declare -A STATE
declare -A INIT

# ---- Command stubs (getters read STATE, setters mutate STATE) ----------------
spctl(){ case "$1" in
  --status) [[ "${STATE[gatekeeper]}" == enabled ]] && echo "assessments enabled" || echo "assessments disabled";;
  --master-enable) STATE[gatekeeper]=enabled;; --master-disable) STATE[gatekeeper]=disabled;; esac; return 0; }

# Application firewall stub. globalstate is 0/1/2; stealth/blockall are
# enabled/disabled, matching socketfilterfw's real output shapes.
socketfilterfw(){ case "$1" in
  --getglobalstate) echo "Firewall is set. (State = ${STATE[fw_global]})";;
  --getstealthmode) echo "Stealth mode ${STATE[fw_stealth]}";;
  --getblockall)    echo "Block all ${STATE[fw_block]}";;
  --setglobalstate) case "$2" in on|On) STATE[fw_global]=1;; off|Off) STATE[fw_global]=0;; esac;;
  --setstealthmode) case "$2" in on|On) STATE[fw_stealth]=enabled;; off|Off) STATE[fw_stealth]=disabled;; esac;;
  --setblockall)    case "$2" in on|On) STATE[fw_block]=enabled;; off|Off) STATE[fw_block]=disabled;; esac;;
  esac; return 0; }

systemsetup(){ case "$1" in
  -getremoteappleevents) echo "Remote Apple Events: ${STATE[rae]}";;
  -setremoteappleevents) case "$2" in on|On) STATE[rae]=On;; off|Off) STATE[rae]=Off;; esac;;
  -getusingnetworktime) echo "Network Time: ${STATE[nettime]}";;
  -setusingnetworktime) case "$2" in on|On) STATE[nettime]=On;; off|Off) STATE[nettime]=Off;; esac;;
  -getnetworktimeserver) echo "Network Time Server: ${STATE[nettimeserver]}";;
  -setnetworktimeserver) STATE[nettimeserver]="$2";; esac; return 0; }

# defaults stub for the configd-owned / SystemConfiguration plists the journal
# owns (a raw cp cannot restore them). Keyed by domain+key so per-key reverts
# (airport association flags, .GlobalPreferences) work. Value is the LAST arg.
defaults(){ local op="$1" domain="$2" key="$3"; local last="${@: -1}" id=""
  case "$domain" in
    *AppleFileServer*) id=afp_guest;;
    *smb.server*) id=smb_guest;;
    *nat*) id=nat;;
    *airport.preferences*) id="airport_$key";;
    *.GlobalPreferences*) id="gp_$key";;
    *) return 0;;
  esac
  case "$op" in
    read)  if [[ -n "${STATE[$id]+x}" ]]; then
             if [[ "$id" == nat ]]; then echo "{ NAT = { Enabled = ${STATE[$id]}; }; }"; else echo "${STATE[$id]}"; fi; return 0
           else return 1; fi;;
    write)
      # Mirror real defaults: -bool only accepts true|false|yes|no. A bare 0/1
      # after -bool is an error (this is exactly the bug the helper must avoid).
      if [[ "$*" == *"-bool"* ]]; then
        case "$last" in
          true|false|yes|no|YES|NO) ;;
          *) echo "defaults: -bool requires true|false" >&2; return 255;;
        esac
      fi
      case "$last" in true|YES|yes) STATE[$id]=1;; false|NO|no) STATE[$id]=0;; *) STATE[$id]="$last";; esac; return 0;;
    delete) unset "STATE[$id]"; return 0;;
  esac; return 0; }

# Not exercised in the round-trip (paranoid authorizationdb revert); stubbed so
# snapshot_system_state's capture probe does not hit the real tools.
security(){ return 1; }
plutil(){ return 1; }

pmset(){ if [[ "$1" == -g ]]; then
    printf ' womp                 %s\n' "${STATE[womp]}"
    printf ' hibernatemode        %s\n' "${STATE[hibernatemode]}"
    printf ' standby              %s\n' "${STATE[standby]}"
  elif [[ "$1" == -a ]]; then STATE[$2]="$3"; fi; return 0; }

networksetup(){ case "$1" in
  -listallhardwareports) printf 'Hardware Port: Wi-Fi\nDevice: en0\n';;
  -getairportpower) echo "Wi-Fi Power ($2): ${STATE[wifi_$2]}";;
  -setairportpower) case "$3" in on|On) STATE[wifi_$2]=On;; off|Off) STATE[wifi_$2]=Off;; esac;;
  -listallnetworkservices) printf 'An asterisk denotes...\nWi-Fi\n';;
  -getinfo) echo "IPv6: ${STATE[ipv6_$2]}";;
  -setv6automatic) STATE[ipv6_$2]=Automatic;; -setv6off) STATE[ipv6_$2]=Off;; esac; return 0; }

nvram(){ if [[ "$1" == -d ]]; then unset "STATE[nvram_$2]"; return 0; fi
  local a="$1"; if [[ "$a" == *=* ]]; then STATE[nvram_${a%%=*}]="${a#*=}"; return 0; fi
  if [[ -n "${STATE[nvram_$a]+x}" ]]; then printf '%s\t%s\n' "$a" "${STATE[nvram_$a]}"; return 0; fi; return 1; }

cupsctl(){ case "$1" in
  --share-printers) STATE[cups_share]=1;; --no-share-printers) STATE[cups_share]=0;;
  *) echo "_share_printers=${STATE[cups_share]}";; esac; return 0; }

launchctl(){ case "$1" in
  list) local k; for k in "${!STATE[@]}"; do [[ "$k" == launchd_* && "${STATE[$k]}" == loaded ]] && echo "${k#launchd_}"; done;;
  load) local l; l="$(basename "$3" .plist)"; STATE[launchd_$l]=loaded;;
  unload) local l; l="$(basename "$3" .plist)"; STATE[launchd_$l]=unloaded;;
  print) return 1;;          # no AEServer/sshd job known -> RAE not journaled
  enable|disable) return 0;; # FDA-independent RAE revert is a no-op in the stub
  esac; return 0; }

pgrep(){ return 1; }   # ARDAgent not running -> ARD revert not recorded (best-effort, excluded)

# Neutralise the destructive / file-restore parts of the rollback (not under test here)
find(){ return 0; }            # restore loop iterates over nothing
killall(){ :; }                # MUST NOT kill the real Finder/cfprefsd
pwpolicy(){ :; }
visudo(){ return 0; }

# Logging stubs used by the sourced backup.sh helpers
debug(){ :; }; info(){ :; }; warn(){ :; }; success(){ :; }; error(){ :; }

DRY_RUN=false
# Point the firewall seam at the function stub so capture + replay stay in-process
# and never touch the real firewall.
export OPSEK_SOCKETFILTERFW=socketfilterfw
IFS=$'\n\t'
source "$REPO/utils/backup.sh"

# =============================================================================
echo "=== TEST A: full capture -> harden -> rollback round-trip (REAL code) ==="
SNAP="$(mktemp -d)/backup_20260101_010101"; mkdir -p "$SNAP"
REVERT_JOURNAL="$SNAP/revert_state.sh"
TIMESTAMP=20260101_010101

# 1) Initial (unhardened) machine
STATE=();
STATE[gatekeeper]=disabled
STATE[fw_global]=0; STATE[fw_stealth]=disabled; STATE[fw_block]=disabled
STATE[smb_guest]=1; STATE[nat]=1   # afp_guest is file-restored, not journaled
STATE[womp]=1; STATE[hibernatemode]=3; STATE[standby]=1
STATE[wifi_en0]=On
STATE[ipv6_Wi-Fi]=Automatic
STATE[cups_share]=1
STATE[launchd_com.apple.screensharing]=loaded
STATE[launchd_com.apple.smbd]=loaded
STATE[launchd_org.cups.cupsd]=loaded
STATE[launchd_com.apple.blued]=loaded
STATE[launchd_com.apple.dhcp6d]=loaded
STATE[launchd_com.apple.bluetoothaudiod]=loaded
STATE[nvram_boot-args]="oldargs"
# airport association flags + system MultipleSessionEnabled are absent before
# Apply (the common real case): capture must journal a DELETE, and Restore must
# remove them again. They are deliberately NOT seeded into STATE here.
# (nvram bluetoothHostControllerSwitchBehavior intentionally unset)

INIT=(); for k in "${!STATE[@]}"; do INIT[$k]="${STATE[$k]}"; done

# 2) REAL capture
init_revert_journal
snapshot_system_state paranoid
echo "  journal entries captured: $(grep -cvE '^[[:space:]]*(#|$)' "$REVERT_JOURNAL")"

# 3) Simulate what the hardening functions do to the system
STATE[gatekeeper]=enabled
STATE[fw_global]=1; STATE[fw_stealth]=enabled; STATE[fw_block]=enabled
STATE[smb_guest]=0; STATE[nat]=0
STATE[womp]=0; STATE[hibernatemode]=25
STATE[wifi_en0]=Off
STATE[ipv6_Wi-Fi]=Off
STATE[cups_share]=0
STATE[launchd_com.apple.screensharing]=unloaded
STATE[launchd_com.apple.smbd]=unloaded
STATE[launchd_org.cups.cupsd]=unloaded
STATE[launchd_com.apple.blued]=unloaded
STATE[launchd_com.apple.dhcp6d]=unloaded
STATE[launchd_com.apple.bluetoothaudiod]=unloaded
STATE[nvram_boot-args]="slide=0 -v"
STATE[nvram_bluetoothHostControllerSwitchBehavior]="never"
# hardening sets the association flags + MultipleSessionEnabled
STATE[airport_DisableAssociation]=1
STATE[airport_AllowEnable]=0
STATE[gp_MultipleSessionEnabled]=0

# 4) REAL rollback generation + execution (file/destructive parts stubbed out).
# Source in the CURRENT shell (not $(...) which is a subshell) so the stubs'
# STATE mutations are observable. Reset set-flags afterward (the rollback runs
# `set -euo pipefail` which would otherwise leak into the assertions).
generate_rollback_script "$SNAP" "$TIMESTAMP"
source "$SNAP/rollback_hardening_$TIMESTAMP.sh" > /tmp/opsek_rb_out.txt 2>&1 || true
set +euo pipefail 2>/dev/null || true
OUT="$(cat /tmp/opsek_rb_out.txt)"

# 5) Assert the system returned to its exact pre-Apply state
for k in "${!INIT[@]}"; do
  if [[ "${STATE[$k]:-__MISSING__}" == "${INIT[$k]}" ]]; then ok "$k restored to '${INIT[$k]}'"; else no "$k = '${STATE[$k]:-__MISSING__}', expected '${INIT[$k]}'"; fi
done
# the nvram bluetooth var must be gone again (was unset initially)
[[ -z "${STATE[nvram_bluetoothHostControllerSwitchBehavior]+x}" ]] && ok "nvram bluetooth override removed (back to unset)" || no "nvram bluetooth override still set: ${STATE[nvram_bluetoothHostControllerSwitchBehavior]}"
# keys absent before Apply must be DELETED again by the revert (not left set)
for absent_key in airport_DisableAssociation airport_AllowEnable gp_MultipleSessionEnabled; do
  [[ -z "${STATE[$absent_key]+x}" ]] && ok "$absent_key removed (back to absent)" || no "$absent_key still set: ${STATE[$absent_key]}"
done
# the rollback must declare clean success (no file restore failures here)
echo "$OUT" | grep -q "OPSEK_ROLLBACK_OK" && ok "rollback printed OPSEK_ROLLBACK_OK" || no "missing OPSEK_ROLLBACK_OK sentinel"

# =============================================================================
echo
echo "=== TEST B: systemsetup without Full Disk Access records no failing revert ==="
# When systemsetup cannot read state (FDA denied), capture must skip RAE/NTP so
# the journal never carries a line guaranteed to warn at replay.
SNAP2="$(mktemp -d)/backup_b"; mkdir -p "$SNAP2"; REVERT_JOURNAL="$SNAP2/revert_state.sh"
STATE=(); STATE[gatekeeper]=enabled; STATE[fw_global]=1; STATE[fw_stealth]=enabled; STATE[fw_block]=disabled
systemsetup(){ echo "setremoteappleevents: requires Full Disk Access" >&2; return 1; }
init_revert_journal
snapshot_system_state recommended
if grep -q "systemsetup" "$REVERT_JOURNAL"; then no "FDA-blocked systemsetup still journaled a revert"; else ok "no systemsetup revert journaled when FDA is denied"; fi
# Firewall must still be captured (to its dedicated file) even when systemsetup is blind.
grep -q -- "--setglobalstate" "$SNAP2/firewall_restore.sh" 2>/dev/null && ok "firewall captured to firewall_restore.sh under no-FDA" || no "firewall capture lost under no-FDA"
# restore the working systemsetup stub for any later use
systemsetup(){ case "$1" in -getremoteappleevents) echo "Remote Apple Events: ${STATE[rae]}";; esac; return 0; }

# =============================================================================
echo
echo "=== TEST C: static lint of the rollback contract ==="
BK="$REPO/utils/backup.sh"
grep -q "! -name 'revert_state.sh'" "$BK" && ok "restore loop excludes revert_state.sh" || no "restore loop does NOT exclude revert_state.sh (would copy journal to /)"
grep -q "! -name '\*.meta'" "$BK" && ok "restore loop excludes *.meta" || no "restore loop does NOT exclude *.meta"
grep -q "OPSEK_ROLLBACK_PARTIAL" "$BK" && ok "rollback can report PARTIAL on file failures" || no "rollback has no PARTIAL sentinel"
grep -q "SystemConfiguration/\*) continue" "$BK" && ok "restore loop skips configd-owned SystemConfiguration plists" || no "restore loop still cp's SystemConfiguration plists"
grep -q "com.apple.alf.plist) continue" "$BK" && ok "restore loop skips daemon-owned com.apple.alf.plist" || no "restore loop still cp's alf.plist (would clobber firewall)"
grep -q "firewall_restore.sh" "$BK" && ok "firewall applied via dedicated last-pass file" || no "no dedicated firewall restore pass"
grep -q "OPSEK_APPLY_OK" "$REPO/utils/common.sh" && ok "apply emits OPSEK_APPLY_OK sentinel" || no "apply has no success sentinel"

# =============================================================================
echo
echo "Result: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]] && { echo "ALL GREEN"; exit 0; } || { echo "SOME FAILED"; exit 1; }
