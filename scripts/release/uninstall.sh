#!/usr/bin/env sh
set -eu

INSTALL_DIR="${AO2_CP_INSTALL_DIR:-${AO2_INSTALL_DIR:-$HOME/.local/bin}}"
for name in \
  ao2-cp-server \
  ao2-cp-gc \
  ao2-control-plane.install-receipt.json \
  .ao2-control-plane.install-receipt.previous.json \
  .ao2-cp-server.ao2-previous \
  .ao2-cp-gc.ao2-previous \
  .ao2-cp-server.ao2-rollback-current \
  .ao2-cp-gc.ao2-rollback-current
do
  rm -f "$INSTALL_DIR/$name"
done
printf 'ao2_control_plane_uninstall=passed\n'
printf 'ao2_control_plane_data_config_preserved=true\n'
