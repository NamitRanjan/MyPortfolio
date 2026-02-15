# Deployment Guide - SOC Automation Dashboard

## Table of Contents
1. [Local Development](#local-development)
2. [Docker Deployment](#docker-deployment)
3. [Cloud Platforms](#cloud-platforms)
4. [Production Considerations](#production-considerations)

---

## Local Development

### Prerequisites
- Python 3.8+
- pip
- Modern web browser

### Steps

1. **Install Dependencies**
```bash
cd backend
pip install -r requirements.txt
```

2. **Start Backend Server**
```bash
python app.py
```
Server runs on `http://localhost:5000`

3. **Serve Frontend**

**Option A: Simple HTTP Server**
```bash
cd frontend
python -m http.server 8080
```

**Option B: Live Server (VS Code)**
- Install Live Server extension
- Right-click `index.html` → "Open with Live Server"

4. **Access Dashboard**
Navigate to `http://localhost:8080`

---

## Docker Deployment

### Using Docker Compose (Recommended)

```bash
# Build and start services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

Access: `http://localhost:8080`

### Manual Docker Build

```bash
# Build image
docker build -t soc-dashboard:latest .

# Run container
docker run -d \
  -p 5000:5000 \
  -p 8080:8080 \
  --name soc-dashboard \
  soc-dashboard:latest

# View logs
docker logs -f soc-dashboard

# Stop container
docker stop soc-dashboard
docker rm soc-dashboard
```

---

## Cloud Platforms

### AWS Elastic Beanstalk

1. **Install EB CLI**
```bash
pip install awsebcli
```

2. **Initialize Application**
```bash
eb init -p python-3.11 soc-dashboard --region us-east-1
```

3. **Create Environment**
```bash
eb create soc-dashboard-prod
```

4. **Deploy Updates**
```bash
eb deploy
```

5. **Open Application**
```bash
eb open
```

### AWS ECS (Elastic Container Service)

1. **Create ECR Repository**
```bash
aws ecr create-repository --repository-name soc-dashboard
```

2. **Build and Push Image**
```bash
# Login to ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin <account-id>.dkr.ecr.us-east-1.amazonaws.com

# Build and tag
docker build -t soc-dashboard .
docker tag soc-dashboard:latest <account-id>.dkr.ecr.us-east-1.amazonaws.com/soc-dashboard:latest

# Push
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/soc-dashboard:latest
```

3. **Create ECS Task Definition and Service** (via AWS Console or CLI)

### Azure App Service

1. **Install Azure CLI**
```bash
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

2. **Login**
```bash
az login
```

3. **Create Resource Group**
```bash
az group create --name soc-dashboard-rg --location eastus
```

4. **Deploy**
```bash
az webapp up \
  --name soc-dashboard \
  --resource-group soc-dashboard-rg \
  --runtime "PYTHON:3.11" \
  --sku B1
```

### Google Cloud Platform

1. **Install gcloud CLI**
```bash
curl https://sdk.cloud.google.com | bash
exec -l $SHELL
gcloud init
```

2. **Create app.yaml**
```yaml
runtime: python311
entrypoint: python backend/app.py

automatic_scaling:
  min_instances: 1
  max_instances: 10
```

3. **Deploy**
```bash
gcloud app deploy
gcloud app browse
```

### Heroku

1. **Install Heroku CLI**
```bash
curl https://cli-assets.heroku.com/install.sh | sh
```

2. **Create Procfile**
```
web: python backend/app.py
```

3. **Deploy**
```bash
heroku login
heroku create soc-dashboard
git push heroku main
heroku open
```

### Vercel (Frontend Only)

```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
cd frontend
vercel
```

### Netlify (Frontend Only)

```bash
# Install Netlify CLI
npm install -g netlify-cli

# Deploy
cd frontend
netlify deploy --prod
```

---

## Production Considerations

### Security

1. **Enable HTTPS**
- Use Let's Encrypt for free SSL certificates
- Configure reverse proxy (Nginx/Apache)

2. **Authentication**
```python
# Add to backend/app.py
from flask_httpauth import HTTPBasicAuth

auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username, password):
    # Implement authentication logic
    return username == 'admin' and password == 'secure-password'

@app.route('/api/protected')
@auth.login_required
def protected():
    return jsonify({'data': 'protected'})
```

3. **Environment Variables**
```bash
# .env file
FLASK_SECRET_KEY=your-secret-key
API_KEY=your-api-key
DATABASE_URL=postgresql://...
```

4. **CORS Configuration**
```python
# Restrict CORS in production
CORS(app, resources={r"/api/*": {"origins": "https://yourdomain.com"}})
```

### Performance

1. **Enable Caching**
```python
from flask_caching import Cache

cache = Cache(app, config={'CACHE_TYPE': 'simple'})

@app.route('/api/cached-endpoint')
@cache.cached(timeout=60)
def cached_endpoint():
    return jsonify({'data': 'cached'})
```

2. **Use Production WSGI Server**
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 backend.app:app
```

3. **Database**
Replace JSON files with proper database:
```python
# PostgreSQL
from flask_sqlalchemy import SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://...'
db = SQLAlchemy(app)
```

### Monitoring

1. **Add Logging**
```python
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/api/endpoint')
def endpoint():
    logger.info('Endpoint accessed')
    return jsonify({'status': 'ok'})
```

2. **Health Check Endpoint**
```python
@app.route('/health')
def health():
    return jsonify({'status': 'healthy'}), 200
```

3. **Monitoring Services**
- New Relic
- Datadog
- Sentry (error tracking)
- CloudWatch (AWS)

### Scaling

1. **Horizontal Scaling**
- Load balancer (AWS ELB, Azure Load Balancer)
- Multiple instances behind load balancer

2. **Caching Layer**
- Redis for session storage
- CDN for static assets (CloudFlare, AWS CloudFront)

3. **Database Optimization**
- Connection pooling
- Read replicas
- Caching layer (Redis, Memcached)

### Backup

1. **Database Backups**
```bash
# Automated backups
pg_dump database_name > backup_$(date +%Y%m%d).sql
```

2. **Configuration Backups**
- Version control for configurations
- Infrastructure as Code (Terraform, CloudFormation)

### CI/CD Pipeline

**GitHub Actions Example:**
```yaml
name: Deploy SOC Dashboard

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Deploy to Production
        run: |
          # Your deployment commands
```

---

## Troubleshooting

### Common Issues

1. **CORS Errors**
- Ensure Flask-CORS is installed
- Check allowed origins

2. **Port Already in Use**
```bash
# Kill process using port
lsof -ti:5000 | xargs kill -9
```

3. **Module Not Found**
```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

4. **Connection Refused**
- Check if backend is running
- Verify API_BASE URL in frontend

---

## Support

For deployment issues:
- Check logs: `docker-compose logs` or `heroku logs --tail`
- Review configuration files
- Contact: namit.ranjan@example.com
