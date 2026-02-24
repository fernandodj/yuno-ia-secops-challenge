.PHONY: help setup demo-logs demo-analyze demo-rotate demo-report test scan-secrets demo-all

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

setup: ## Install Python dependencies
	pip install -r hardened-integration/requirements.txt

# --- Incident Response Demos ---

demo-logs: ## Generate sample API access logs
	cd incident-response && python sample_data/generate_sample_logs.py \
		--output sample_data/sample_api_logs.jsonl --count 500

demo-analyze: demo-logs ## Analyze sample logs for anomalies (generates logs first)
	cd incident-response && python analyze_api_logs.py \
		--log-file sample_data/sample_api_logs.jsonl \
		--leak-timestamp 2024-01-15T03:47:00+00:00 \
		--merchant-id merchant_quickeats_prod_001 \
		--output-json sample_data/analysis_report.json

demo-rotate: ## Demo credential rotation (dry run)
	cd incident-response && python rotate_credentials.py \
		--merchant-id merchant_quickeats_prod_001 \
		--environment production \
		--dry-run

demo-report: demo-analyze ## Generate incident report (runs analysis first)
	cd incident-response && python generate_report.py \
		--merchant-id merchant_quickeats_prod_001 \
		--leak-timestamp 2024-01-15T03:47:00+00:00 \
		--analyst-name "Yuno SOC Analyst" \
		--findings-file sample_data/analysis_report.json \
		--output sample_data/incident_report.md
	@echo "\nReport generated at: incident-response/sample_data/incident_report.md"

# --- Tests ---

test: ## Run all security control tests
	cd hardened-integration && python -m pytest tests/ -v --tb=short

test-webhooks: ## Run webhook verification tests only
	cd hardened-integration && python -m pytest tests/test_webhook_verification.py -v

test-timing: ## Run timing attack resistance tests
	cd hardened-integration && python -m pytest tests/test_timing_attack.py -v

test-audit: ## Run audit logging / PAN masking tests
	cd hardened-integration && python -m pytest tests/test_audit_logger.py -v

# --- Secrets Scanning ---

scan-secrets: ## Run Gitleaks against test samples
	@echo "Scanning test-samples for intentionally embedded secrets..."
	@cd secrets-scanning && gitleaks detect --source test-samples/ \
		--config gitleaks.toml --verbose --no-git 2>&1 || true
	@echo "\n(Findings above are expected — these are intentional test secrets)"

# --- Full Demo ---

demo-all: demo-analyze demo-rotate demo-report test ## Run everything: analysis + rotation + report + tests
	@echo "\n========================================="
	@echo "  All demos and tests completed!"
	@echo "========================================="
