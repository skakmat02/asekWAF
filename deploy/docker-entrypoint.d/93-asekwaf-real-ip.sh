#!/bin/sh
set -eu

output=/etc/nginx/conf.d/01-asekwaf-real-ip.conf
header=${REAL_IP_HEADER:-X-Forwarded-For}
recursive=${REAL_IP_RECURSIVE:-on}
trusted=${SET_REAL_IP_FROM:-127.0.0.1}

case "$header" in
  *[!A-Za-z0-9_-]*|'')
    echo "[asekwaf] Invalid REAL_IP_HEADER: $header" >&2
    exit 1
    ;;
esac

case "$recursive" in
  on|off) ;;
  *)
    echo "[asekwaf] REAL_IP_RECURSIVE must be on or off" >&2
    exit 1
    ;;
esac

{
  echo '# AsekWAF trusted reverse-proxy client IP configuration.'
  old_ifs=$IFS
  IFS=','
  for address in $trusted; do
    IFS=$old_ifs
    address=$(printf '%s' "$address" | tr -d '[:space:]')
    case "$address" in
      ''|*[!A-Fa-f0-9:./_-]*)
        echo "[asekwaf] Invalid SET_REAL_IP_FROM entry: $address" >&2
        exit 1
        ;;
    esac
    printf 'set_real_ip_from %s;\n' "$address"
    IFS=','
  done
  IFS=$old_ifs
  printf 'real_ip_header %s;\n' "$header"
  printf 'real_ip_recursive %s;\n' "$recursive"
} > "$output"

echo "[asekwaf] Real client IP enabled for trusted proxy: $trusted ($header)"
