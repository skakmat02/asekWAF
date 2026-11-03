SHELL := /bin/sh

.PHONY: init up down logs ps build check audit production-check production-up production-down dev reload reset-crs reset-all backup

init:
	@test -f .env || cp .env.example .env
	@mkdir -p deploy/modsec deploy/nginx deploy/logs
	@test -f deploy/modsec/modsecurity-override.conf || cp deploy/examples/modsecurity-override.conf deploy/modsec/modsecurity-override.conf
	@test -f deploy/nginx/default-upstream.conf || cp deploy/examples/default-upstream.conf deploy/nginx/default-upstream.conf
	@test -f deploy/nginx/sites.conf || cp deploy/examples/sites.conf deploy/nginx/sites.conf
	@test -f deploy/nginx/rate-limit-zone.conf || cp deploy/examples/rate-limit-zone.conf deploy/nginx/rate-limit-zone.conf
	@test -f deploy/nginx/rate-limit-location.conf || cp deploy/examples/rate-limit-location.conf deploy/nginx/rate-limit-location.conf

up: init
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f --tail=120

ps:
	docker compose ps

build: init
	docker compose build

check:
	node --check manager/server.js
	node --check manager/public/app.js
	node --check manager/lib/util.js
	node --check manager/lib/config.js
	node --check manager/lib/state.js
	node --check manager/lib/render.js
	node --check manager/lib/crs.js
	node --check manager/lib/audit.js
	node --check manager/lib/docker.js
	node --check manager/lib/auth.js
	npm audit --omit=dev --prefix manager

audit:
	npm audit --omit=dev --prefix manager

production-check: init
	@sh scripts/production-check.sh .env.production
	docker compose --env-file .env.production config --quiet

production-up: production-check
	docker compose --env-file .env.production up -d --build

production-down:
	docker compose --env-file .env.production down

# Jalankan manager tanpa Docker memakai fixture CRS lokal.
# Reload WAF akan dilewati (Docker socket tidak tersedia).
dev:
	CRS_DIR=$(CURDIR)/test/fixtures/crs \
	AUDIT_LOG=$(CURDIR)/test/fixtures/logs/audit.log \
	OPENWAF_ADMIN_PASSWORD=admin \
	MANAGER_PORT=8081 \
	node manager/server.js

# Reload manual di dalam container (tanpa validasi/rollback dari panel).
reload:
	docker compose exec -T waf /usr/sbin/nginx -t
	docker compose exec -T waf /usr/sbin/nginx -s reload

# Seed ulang rules CRS dari image. State AsekWAF (custom rule, exclusion,
# IP list, reverse proxy) tetap tersimpan di deploy/modsec.
reset-crs:
	docker compose down
	-docker volume rm asekwaf_crsdata
	docker compose up -d

# Hapus semua container + volume (termasuk audit log). State di deploy/modsec
# tidak ikut terhapus.
reset-all:
	docker compose down -v

backup:
	@mkdir -p backup
	@tar czf backup/asekwaf-$$(date +%Y%m%d-%H%M%S).tar.gz deploy .env 2>/dev/null || true
	@echo "Backup dibuat di folder backup/."
