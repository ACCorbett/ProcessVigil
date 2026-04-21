# Draws colored security-context overlays on Windows:
#   Red    — SYSTEM context
#   Orange — Elevated / Admin (same user, UAC-elevated)
#   Yellow — Different user (RunAs / impersonation)
#
# Requires: PowerShell 7+, Windows 10/11, elevated (admin) session
# Optional: Security audit policy for Chrome/Edge detection
#           auditpol /set /subcategory:"Process Creation" /success:enable
