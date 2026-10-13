#!/bin/bash
# isp-select.sh — switch bb0's WAN between the two ISPs, either direction.
#
#   isp-select.sh new      -> new ISP: PPPoE on ppp0  (NM 'bb-wan-pppoe')
#   isp-select.sh old      -> old ISP: DHCP  on eth0  (NM 'bb-wan')
#   isp-select.sh status   -> show which ISP is active and the firewall target
#
# PHYSICAL: eth0's cable must already be on the right upstream — the ONT for
# 'new', the old ISP box for 'old'. The software can't move the cable, but if
# the target WAN fails to come up it AUTO-REVERTS to the previous connection so
# a premature run (or wrong cable) never strands you without internet.
#
# The firewall is only repointed AFTER the target WAN is confirmed up, so a
# failed switch leaves NAT/forwarding consistent with the reverted connection.
set -u
LOG=/var/log/beaconbutty/isp-cutover.log
mkdir -p "$(dirname "$LOG")"
say(){ echo "[$(date '+%F %T')] select: $*" | tee -a "$LOG" ; }

CONN_NEW=bb-wan-pppoe
CONN_OLD=bb-wan
IF_NEW=ppp0
IF_OLD=eth0
WAIT=30     # seconds to wait for the target WAN to come up before reverting

active_conn(){ nmcli -t -f NAME,DEVICE con show --active | awk -F: '$1=="'"$CONN_NEW"'"||$1=="'"$CONN_OLD"'"{print $1; exit}'; }
wan_iface_now(){ ip -4 route show default 2>/dev/null | awk '$0!~/wlan0/{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'; }

# Point NAT/forward/MSS/WAN-input at $1, removing the other WAN iface's rules.
fw_point_wan(){
  local want="$1" other
  [ "$want" = "$IF_NEW" ] && other="$IF_OLD" || other="$IF_NEW"
  # NAT masquerade
  iptables -t nat -D POSTROUTING -o "$other" -j MASQUERADE 2>/dev/null
  iptables -t nat -C POSTROUTING -o "$want" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$want" -j MASQUERADE
  # FORWARD both directions
  iptables -D FORWARD -i eth1 -o "$other" -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
  iptables -D FORWARD -i "$other" -o eth1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
  iptables -C FORWARD -i eth1 -o "$want" -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i eth1 -o "$want" -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
  iptables -C FORWARD -i "$want" -o eth1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$want" -o eth1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  # MSS clamp: needed on PPPoE (1492). Remove the other's, add for a ppp* want.
  iptables -t mangle -D FORWARD -o "$other" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null
  if [[ "$want" == ppp* ]]; then
    iptables -t mangle -C FORWARD -o "$want" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A FORWARD -o "$want" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  fi
  # WAN input policy for ppp0 (eth0's base drop/accept come from harden.sh and
  # are permanent + harmless when eth0 isn't the WAN, so we only manage ppp0's).
  if [[ "$want" == ppp* ]]; then
    iptables -C INPUT -i "$want" -p udp --dport 41641 -j ACCEPT 2>/dev/null || iptables -A INPUT -i "$want" -p udp --dport 41641 -j ACCEPT
    iptables -C INPUT -i "$want" -j DROP 2>/dev/null || iptables -A INPUT -i "$want" -j DROP
  else
    iptables -D INPUT -i "$IF_NEW" -p udp --dport 41641 -j ACCEPT 2>/dev/null
    iptables -D INPUT -i "$IF_NEW" -j DROP 2>/dev/null
  fi
  iptables-save > /etc/iptables/rules.v4
  say "firewall repointed to $want (+ rules.v4 saved)"
}

wait_up(){   # $1 = iface
  local i
  for i in $(seq 1 "$WAIT"); do
    ip -4 addr show "$1" 2>/dev/null | grep -q 'inet ' && ip route show default | grep -q "dev $1" && return 0
    sleep 1
  done
  return 1
}

do_status(){
  local a; a=$(active_conn)
  echo "Active NM WAN connection : ${a:-none}"
  echo "WAN interface (route)    : $(wan_iface_now)"
  echo "Public IP                : $(ip -4 addr show "$(wan_iface_now)" 2>/dev/null | awk '/inet /{print $2; exit}')"
  echo "NAT masquerade out-iface : $(iptables -t nat -S POSTROUTING | awk '/MASQUERADE/ && /-o /{for(i=1;i<=NF;i++) if($i=="-o") print $(i+1)}' | tr '\n' ' ')"
  echo "wan-watchdog.timer       : $(systemctl is-active wan-watchdog.timer 2>/dev/null)"
  ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 && echo "Internet                 : OK" || echo "Internet                 : DOWN"
}

switch(){   # $1 target: new|old
  local target="$1" conn_to conn_from if_to upstream prev
  if [ "$target" = new ]; then conn_to=$CONN_NEW; conn_from=$CONN_OLD; if_to=$IF_NEW; upstream="the ONT"
  else                         conn_to=$CONN_OLD; conn_from=$CONN_NEW; if_to=$IF_OLD; upstream="the OLD ISP box"; fi

  prev=$(active_conn)
  say "switching to '$target' ($conn_to / $if_to). cable must be on $upstream."
  if [ "$prev" = "$conn_to" ] && wait_up "$if_to"; then
    say "already on $conn_to and $if_to is up — reasserting firewall/autoconnect only"
  else
    nmcli con down "$conn_from" 2>/dev/null && say "$conn_from down"
    nmcli con up   "$conn_to"   2>/dev/null && say "$conn_to up"
  fi

  if ! wait_up "$if_to"; then
    say "FAIL: $if_to did not come up within ${WAIT}s — cable probably not on $upstream."
    if [ -n "$prev" ] && [ "$prev" != "$conn_to" ]; then
      say "AUTO-REVERT -> $prev (restoring previous working WAN)"
      nmcli con down "$conn_to" 2>/dev/null
      nmcli con up   "$prev"    2>/dev/null
      say "reverted. move the cable to $upstream, then re-run: isp-select.sh $target"
    fi
    return 2
  fi

  fw_point_wan "$if_to"
  # Deterministic boot: selected conn autoconnects, the other does not.
  nmcli con modify "$conn_to"   connection.autoconnect yes 2>/dev/null
  nmcli con modify "$conn_from" connection.autoconnect no  2>/dev/null
  # Hint for the watchdog's runtime WAN detection when the WAN is fully down and
  # it cannot read the default route: new -> pppoe (ppp0), old -> dhcp (eth0).
  mkdir -p /var/lib/beaconbutty
  [ "$target" = new ] && echo pppoe > /var/lib/beaconbutty/wan-mode \
                      || echo dhcp  > /var/lib/beaconbutty/wan-mode
  say "wan-mode hint -> $([ "$target" = new ] && echo pppoe || echo dhcp)"

  # Watchdog: the DHCP/eth0 model works on 'old'; it is paused on 'new' until the
  # ppp0 diagnostic rework lands (tasks/todo.md step 6).
  if [ "$target" = old ]; then systemctl start wan-watchdog.timer 2>/dev/null && say "wan-watchdog.timer started (eth0 model)"
  else systemctl stop wan-watchdog.timer 2>/dev/null && say "wan-watchdog.timer stopped (needs ppp0 rework)"; fi

  sleep 2
  ping -c2 -W3 1.1.1.1 >/dev/null 2>&1 && say "DONE: on '$target', internet OK ($(ip -4 addr show "$if_to"|awk '/inet /{print $2;exit}'))" \
                                        || say "DONE: on '$target' but no internet yet — check upstream."
}

case "${1:-}" in
  new|old) [ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }; switch "$1" ;;
  status)  do_status ;;
  *) echo "usage: $0 {new|old|status}"; exit 1 ;;
esac
