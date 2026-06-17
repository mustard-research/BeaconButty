#!/usr/bin/env bash
# Fan threshold tuning for bb0 (Pi 5)
#
# Default fan-on temp is 50°C. With bb0 idling at 45–51°C, the fan runs almost
# constantly. Raising the threshold to 60°C reduces fan wear with no thermal
# risk — throttling only begins at 80°C.
#
# Apply with: sudo bash scripts/fan-tune.sh
# Revert by removing the dtparam lines from /boot/firmware/config.txt and rebooting.

set -euo pipefail

CONFIG=/boot/firmware/config.txt

# Check if already applied
if grep -q 'fan_temp0=60000' "$CONFIG"; then
    echo "Fan tuning already applied — nothing to do."
    exit 0
fi

echo "Applying fan threshold changes to $CONFIG ..."

cat >> "$CONFIG" <<'EOF'

# Fan threshold tuning — raise trip point from 50°C to 60°C to reduce wear.
# 5°C hysteresis prevents rapid on/off cycling.
# Safe: throttling begins at 80°C; bb0 idles at 45–51°C.
dtparam=fan_temp0=60000,fan_temp0_hyst=5000,fan_temp0_speed=75
dtparam=fan_temp1=67500,fan_temp1_hyst=5000,fan_temp1_speed=125
dtparam=fan_temp2=75000,fan_temp2_hyst=5000,fan_temp2_speed=175
dtparam=fan_temp3=82500,fan_temp3_hyst=5000,fan_temp3_speed=250
EOF

echo "Done. Reboot to activate: sudo reboot"
