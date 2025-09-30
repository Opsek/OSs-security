#!/usr/bin/env bash

module_main() {
  log_info "Summary of changes"
  echo "Backups stored in: $HARDEN_BACKUP_DIR_BASE/$RUN_STAMP" | tee -a "$HARDEN_LOG_FILE" >/dev/null
  echo "Log file: $HARDEN_LOG_FILE" | tee -a "$HARDEN_LOG_FILE" >/dev/null
  echo "Platform: $PLATFORM_ID $PLATFORM_VERSION ($PLATFORM_FAMILY)" | tee -a "$HARDEN_LOG_FILE" >/dev/null
}


