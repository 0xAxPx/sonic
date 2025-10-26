# 🛡️ Cybersecurity Threat Detector

A real-time network threat detection system using Machine Learning to identify malicious network traffic patterns.

## 🎯 Project Overview

This system analyzes network traffic in real-time and uses a trained Random Forest ML model to detect potential cybersecurity threats. It consists of:

- **ML Service** (Python/FastAPI) - Serves ML predictions
- **Ingestion Service** (Go) - Processes network traffic data
- **API Gateway** (Go) - REST API for accessing system data
- **Dashboard** (React) - Real-time monitoring interface
- **PostgreSQL** - Data storage
- **Redis** - Caching layer

## 📋 Prerequisites

Before starting, ensure you have installed:

- **Docker** (>= 20.10)
- **Docker Compose** (>= 2.0)
- **Go** (>= 1.21) - for local development
- **Python** (>= 3.11) - for ML training
- **Node.js** (>= 18) - for React development

## 🚀 Quick Start

### 1. Clone and Setup

```bash
# Clone the repository
cd sonic

# Copy environment file
cp .env.example .env

# Review and update .env if needed
```

### 2. Start All Services with Docker Compose

```bash
# Build and start all services
docker-compose up --build

# Or run in detached mode
docker-compose up -d
```

This will start:
- PostgreSQL on port 5432
- Redis on port 6379
- ML Service on port 8000
- Ingestion Service on port 8080
- API Gateway on port 3000
- Dashboard on port 80

### 3. Verify Services

```bash
# Check all services are running
docker-compose ps

# Check ML Service health
curl http://localhost:8000/health

# Check API Gateway health
curl http://localhost:3000/health

# Check Ingestion Service health
curl http://localhost:8080/health
```

### 4. Access the Dashboard

Open your browser and navigate to:
```
http://localhost
```

You should see the Threat Detector Dashboard with real-time statistics.

## 📁 Project Structure

```
sonic/
├── ml-service/              # Python/FastAPI ML service
│   ├── app/
│   │   └── main.py         # FastAPI application
│   ├── model/              # Trained model storage
│   ├── training/           # Model training scripts (to be added)
│   ├── requirements.txt
│   └── Dockerfile
│
├── ingestion-service/       # Go data ingestion service
│   ├── handlers/
│   ├── models/
│   ├── utils/
│   ├── main.go
│   ├── go.mod
│   └── Dockerfile
│
├── api-gateway/            # Go REST API gateway
│   ├── routes/
│   ├── middleware/
│   ├── models/
│   ├── main.go
│   ├── go.mod
│   └── Dockerfile
│
├── dashboard/              # React dashboard
│   ├── src/
│   │   ├── App.js
│   │   ├── App.css
│   │   └── index.js
│   ├── public/
│   ├── package.json
│   ├── nginx.conf
│   └── Dockerfile
│
├── database/
│   └── schema.sql         # PostgreSQL schema
│
├── docs/                  # Documentation
│
├── docker-compose.yml
├── .env.example
└── README.md
```

## 🔧 Development Setup

### Local Development (Without Docker)

#### 1. Start PostgreSQL and Redis

```bash
# Using Docker for DB only
docker-compose up postgres redis -d
```

#### 2. Run ML Service Locally

```bash
cd ml-service

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the service
uvicorn app.main:app --reload --port 8000
```

#### 3. Run Ingestion Service Locally

```bash
cd ingestion-service

# Download Go dependencies
go mod download

# Run the service
go run main.go
```

#### 4. Run API Gateway Locally

```bash
cd api-gateway

# Download Go dependencies
go mod download

# Run the service
go run main.go
```

#### 5. Run React Dashboard Locally

```bash
cd dashboard

# Install dependencies
npm install

# Start development server
npm start
```

## 📚 API Documentation

### ML Service Endpoints

- **GET** `/health` - Health check
- **POST** `/predict` - Single prediction
- **POST** `/predict/batch` - Batch predictions

**Example prediction request:**
```bash
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{
    "duration": 0.5,
    "protocol_type": "tcp",
    "service": "http",
    "flag": "SF",
    "src_bytes": 181,
    "dst_bytes": 5450,
    ...
  }'
```

### API Gateway Endpoints

All endpoints require `X-API-Key` header with value `dev-api-key-12345` (for development).

- **GET** `/api/v1/alerts` - Get all alerts
- **GET** `/api/v1/alerts/:id` - Get specific alert
- **PATCH** `/api/v1/alerts/:id` - Update alert status
- **GET** `/api/v1/stats` - Get system statistics
- **GET** `/api/v1/threats` - Get detected threats
- **POST** `/api/v1/analyze` - Analyze traffic

**Example:**
```bash
curl -X GET http://localhost:3000/api/v1/stats \
  -H "X-API-Key: dev-api-key-12345"
```

## 🧪 Testing

```bash
# Test ML Service
curl http://localhost:8000/health

# Test API Gateway with auth
curl -H "X-API-Key: dev-api-key-12345" http://localhost:3000/api/v1/stats

# Check database
docker-compose exec postgres psql -U postgres -d threat_detector -c "SELECT COUNT(*) FROM network_traffic;"
```

## 📊 Training the ML Model

The ML model needs to be trained before the system can make predictions.

```bash
cd ml-service

# Download NSL-KDD dataset
# (Instructions will be added in training script)

# Run training script (to be implemented in Week 3-4)
python training/train_model.py

# The trained model will be saved to ml-service/model/rf_model.pkl
```

## 🐛 Troubleshooting

### Services won't start
```bash
# Check logs
docker-compose logs ml-service
docker-compose logs api-gateway

# Restart specific service
docker-compose restart ml-service
```

### Port already in use
```bash
# Find process using port
lsof -i :8000  # Mac/Linux
netstat -ano | findstr :8000  # Windows

# Kill the process or change port in docker-compose.yml
```

### Database connection issues
```bash
# Check PostgreSQL is running
docker-compose ps postgres

# Check database logs
docker-compose logs postgres

# Manually connect to database
docker-compose exec postgres psql -U postgres -d threat_detector
```

### ML Model not loaded
The ML service will start without a model but won't be able to make predictions. You need to:
1. Train the model first (Week 3-4 of implementation plan)
2. Place the trained model in `ml-service/model/rf_model.pkl`
3. Restart the ML service

## 🔐 Security Notes

**⚠️ IMPORTANT:** The current setup is for DEVELOPMENT ONLY.

For production deployment:
- Change all default passwords and API keys
- Use environment-specific .env files
- Enable SSL/TLS for all services
- Implement proper authentication (JWT, OAuth)
- Use secrets management (AWS Secrets Manager, HashiCorp Vault)
- Enable database encryption
- Set up proper logging and monitoring
- Configure firewall rules

## 📈 Monitoring

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f ml-service
docker-compose logs -f api-gateway
```

### Database Queries

```bash
# Connect to database
docker-compose exec postgres psql -U postgres -d threat_detector

# View recent threats
SELECT * FROM threat_predictions WHERE prediction = 'malicious' ORDER BY created_at DESC LIMIT 10;

# View alerts
SELECT * FROM alerts ORDER BY created_at DESC LIMIT 10;

# View statistics
SELECT * FROM threat_stats;
```

## 🛠️ Next Steps

This is the MVP skeleton. Next steps according to the implementation plan:

**Week 3-4:** Train the ML model
**Week 5-6:** Implement ML service endpoints fully
**Week 7:** Complete ingestion service with real data processing
**Week 8:** Implement all API Gateway endpoints
**Week 9:** Enhance dashboard with charts and real-time updates
**Week 10:** Testing, deployment, and documentation

## 📝 License

This project is for educational and portfolio purposes.

## 🤝 Contributing

This is a personal project, but feedback and suggestions are welcome!

## 📧 Contact

For questions or feedback, please open an issue.

---

**Status:** 🟡 MVP Skeleton Complete - Ready for implementation (Week 1-2 ✅)