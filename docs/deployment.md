# Production Deployment Guide

## Docker Compose (Recommended for Small-Medium Deployments)

```bash
# Clone the repo
git clone https://github.com/agentshield/agentshield
cd agentshield/infra

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Start the stack
docker-compose up -d

# Run migrations
docker-compose exec server alembic upgrade head
```

## Kubernetes (Large-Scale Production)

### Prerequisites
- Kubernetes cluster
- kubectl configured
- Container registry with images pushed

### Deploy

```bash
# Create namespace
kubectl create namespace agentshield

# Create secrets
kubectl create secret generic agentshield-secrets \
  --from-literal=database-url="postgresql+asyncpg://user:pass@host/db" \
  --from-literal=admin-api-key="$(openssl rand -hex 32)" \
  -n agentshield

# Apply manifests
kubectl apply -f infra/kubernetes/

# Check status
kubectl get pods -n agentshield
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Database connection string | SQLite |
| `ADMIN_API_KEY` | Admin API key | (required in prod) |
| `SECRET_KEY` | JWT signing key | (required in prod) |
| `SLACK_WEBHOOK_URL` | Slack notifications | (optional) |
| `REDIS_URL` | Redis for pub/sub | (optional) |
| `AUTO_BLOCK_CRITICAL` | Auto-block critical threats | true |
| `EVENT_RETENTION_DAYS` | Days to retain events | 90 |

## Production Checklist

- [ ] Change `ADMIN_API_KEY` from default
- [ ] Set strong `SECRET_KEY`
- [ ] Configure PostgreSQL (not SQLite)
- [ ] Enable HTTPS via nginx/ingress
- [ ] Configure Slack/email notifications
- [ ] Set up automated backups for PostgreSQL
- [ ] Review and tune policy thresholds
- [ ] Configure `allowed_tools` in SDK for each agent
