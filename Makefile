-include .env
export

ALIAS ?= greentic-rp
CLIENT_REG ?= dynamic_client
REQUEST_TYPE ?= plain_http_request
CONFIG_JSON ?= ci/plans/examples/rp-code-pkce-basic.config.json
USE_TUNNEL ?= 1
RP_LOCAL_URL ?= http://localhost:8080
CS_URL ?= https://www.certification.openid.net

.PHONY: test e2e ci conformance.plan conformance.full

test:
	cargo test --workspace --all-features -- --nocapture

e2e:
	CI_ENABLE_OAUTH_MOCK=1 cargo test --test oauth --features oauth -- --nocapture

ci:
	./scripts/ci.sh

conformance.plan:
	@set -a; . ./.env; set +a; \
	bash ci/scripts/run_conformance_hosted_with_tunnel.sh || { \
		status=$$?; \
		echo >&2 "[make] conformance.plan failed (exit $$status). See logs above for details, then verify your .env settings (CS_TOKEN, RP_BASE, etc.)."; \
		exit $$status; \
	}

# conformance.full drives the hosted OIDF suite end-to-end without a
# tunnel: creates the plan automatically (no manual UI step), runs
# every module, and collects reports. Suitable for scheduled CI against
# a publicly-reachable RP.
#
# Required env (typically supplied by the workflow as repo secrets):
#   CS_URL or OIDF_CS_URL    - hosted suite base URL (e.g. https://www.certification.openid.net)
#   CS_TOKEN or OIDF_CS_TOKEN- API token from the hosted UI
#   RP_METADATA_URL          - RP discovery doc, e.g. https://rp.example.com/.well-known/openid-configuration
conformance.full:
	@: $${CS_URL:?CS_URL is required for conformance.full}
	@: $${CS_TOKEN:?CS_TOKEN is required for conformance.full}
	@: $${RP_METADATA_URL:?RP_METADATA_URL is required for conformance.full}
	@rp_base="$$(printf '%s' "$$RP_METADATA_URL" | sed -E 's|/\.well-known/openid-configuration/?$$||')"; \
	echo "[make] conformance.full RP_BASE_URL=$$rp_base CONFIG_JSON=$(CONFIG_JSON)"; \
	mkdir -p reports; \
	SUITE_BASE="$$CS_URL" \
	SUITE_API_KEY="$$CS_TOKEN" \
	RP_BASE_URL="$$rp_base" \
	ALIAS="$(ALIAS)" \
	bash ci/scripts/run_conformance_plan.sh "$(CONFIG_JSON)" || { \
		status=$$?; \
		echo >&2 "[make] conformance.full failed (exit $$status); collecting reports anyway."; \
		SUITE_BASE="$$CS_URL" SUITE_API_KEY="$$CS_TOKEN" \
			bash ci/scripts/collect_reports.sh || true; \
		exit $$status; \
	}; \
	SUITE_BASE="$$CS_URL" SUITE_API_KEY="$$CS_TOKEN" \
		bash ci/scripts/collect_reports.sh
