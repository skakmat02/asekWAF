#!/bin/sh
set -eu

env_file=${1:-.env.production}
[ -f "$env_file" ] || { echo "ERROR: $env_file tidak ditemukan" >&2; exit 1; }

value_of() {
  sed -n "s/^$1=//p" "$env_file" | tail -n 1
}

password=$(value_of OPENWAF_ADMIN_PASSWORD)
secret=$(value_of OPENWAF_SESSION_SECRET)
crs_image=$(value_of CRS_IMAGE)
proxy_image=$(value_of DOCKER_SOCKET_PROXY_IMAGE)
production_mode=$(value_of OPENWAF_PRODUCTION)
secure_cookie=$(value_of OPENWAF_COOKIE_SECURE)

[ ${#password} -ge 16 ] || { echo "ERROR: password produksi minimal 16 karakter" >&2; exit 1; }
[ ${#secret} -ge 32 ] || { echo "ERROR: session secret produksi minimal 32 karakter" >&2; exit 1; }
[ "$password" != "GANTI-DENGAN-PASSWORD-UNIK-MINIMAL-16-KARAKTER" ] || { echo "ERROR: password masih placeholder" >&2; exit 1; }
[ "$secret" != "GANTI-DENGAN-STRING-ACAK-MINIMAL-32-KARAKTER" ] || { echo "ERROR: session secret masih placeholder" >&2; exit 1; }
[ -n "$crs_image" ] || { echo "ERROR: CRS_IMAGE wajib diisi" >&2; exit 1; }
[ -n "$proxy_image" ] || { echo "ERROR: DOCKER_SOCKET_PROXY_IMAGE wajib diisi" >&2; exit 1; }
[ "$production_mode" = "true" ] || { echo "ERROR: OPENWAF_PRODUCTION harus true" >&2; exit 1; }
[ "$secure_cookie" = "true" ] || { echo "ERROR: OPENWAF_COOKIE_SECURE harus true" >&2; exit 1; }
case "$crs_image $proxy_image" in
  *:latest*|*:nginx*) echo "ERROR: image produksi harus memakai versi/digest tetap, bukan moving tag" >&2; exit 1 ;;
esac

echo "Production environment check: OK"
