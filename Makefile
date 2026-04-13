.PHONY: dev test build deploy clean install

dev:
	@echo "Starting AgentShield development environment..."
	cd infra && docker-compose -f docker-compose.dev.yml up -d
	@echo "Server: http://localhost:8000"
	@echo "Dashboard: http://localhost:3000"
	@echo "API Docs: http://localhost:8000/docs"

dev-server:
	cd server && uvicorn main:app --reload --port 8000

dev-dashboard:
	cd dashboard && npm run dev

test:
	@echo "Running test suite..."
	cd server && pytest ../tests/server/ -v
	cd sdk && pytest ../tests/sdk/ -v
	cd threat-intel && pytest ../tests/threat-intel/ -v

test-coverage:
	pytest tests/ --cov=sdk/agentshield --cov=server --cov-report=html

build:
	@echo "Building Docker images..."
	docker build -t agentshield-server:latest ./server
	docker build -t agentshield-dashboard:latest ./dashboard

build-sdk:
	cd sdk && python -m build

install-sdk:
	cd sdk && pip install -e ".[dev]"

install-cli:
	cd cli && pip install -e .

deploy:
	@echo "Deploying to Kubernetes..."
	kubectl apply -f infra/kubernetes/

deploy-docker:
	cd infra && docker-compose up -d

stop:
	cd infra && docker-compose down

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf dashboard/dist dashboard/node_modules/.cache
	rm -f agentshield.db *.sqlite3

lint:
	ruff check sdk/ server/ cli/ tests/
	cd dashboard && npm run lint

format:
	ruff format sdk/ server/ cli/ tests/
	cd dashboard && npm run format

migrate:
	cd server && alembic upgrade head

migrate-new:
	cd server && alembic revision --autogenerate -m "$(msg)"

docs-serve:
	cd docs && python -m http.server 8080

setup: install-sdk install-cli
	@echo "AgentShield development environment ready!"
	@echo "Run 'make dev' to start the full stack"
