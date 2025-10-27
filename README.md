# 🛡️ Sonic - Network Threat Detector

A real-time cybersecurity threat detection system using Machine Learning to identify and classify malicious network traffic patterns.

## 🎯 What Does Sonic Do?

Sonic monitors network traffic in real-time and uses a trained Random Forest ML model to:
- **Detect** malicious network activity patterns
- **Classify** threat types (DoS, Probe, R2L, U2R attacks)
- **Alert** security teams with severity levels
- **Visualize** threats through a real-time dashboard

---

## 🏗️ System Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                         SONIC ARCHITECTURE                       │
└─────────────────────────────────────────────────────────────────┘

                         ┌──────────────┐
                         │   Dashboard  │
                         │   (React)    │
                         │   Port: 80   │
                         └──────┬───────┘
                                │ HTTP
                                ▼
                         ┌──────────────┐
                         │ API Gateway  │
                         │    (Go)      │
                         │  Port: 3000  │
                         └──────┬───────┘
                                │
                ┌───────────────┼───────────────┐
                │               │               │
                ▼               ▼               ▼
         ┌──────────┐    ┌──────────┐   ┌──────────┐
         │Ingestion │    │PostgreSQL│   │  Redis   │
         │ Service  │    │   (DB)   │   │ (Cache)  │
         │   (Go)   │    │Port: 5432│   │Port: 6379│
         │Port: 8080│    └──────────┘   └──────────┘
         └─────┬────┘
               │
               ▼
         ┌──────────┐
         │ML Service│
         │ (FastAPI)│
         │Port: 8000│
         └──────────┘

DATA FLOW:
1. Network Traffic → Ingestion Service
2. Ingestion Service → ML Service (prediction request)
3. ML Service → Returns: "normal" or "malicious" + confidence
4. Ingestion Service → Stores in PostgreSQL
5. If malicious → Creates Alert
6. Dashboard → Queries API Gateway → Shows real-time stats
```

---

## 🎯 Threat Detection Capabilities

Sonic detects **4 major attack categories** based on NSL-KDD dataset:

### **1. DoS (Denial of Service)**
- **What:** Overwhelm system resources to make services unavailable
- **Examples:** SYN flood, UDP flood, Ping of Death
- **Detection:** High packet rate, abnormal connection patterns

### **2. Probe (Reconnaissance)**
- **What:** Scanning/probing to gather information about systems
- **Examples:** Port scans, IP sweeps, vulnerability scanners
- **Detection:** Multiple connection attempts, failed logins

### **3. R2L (Remote to Local)**
- **What:** Unauthorized remote access attempts
- **Examples:** Password guessing, buffer overflow exploits
- **Detection:** Failed authentication, suspicious protocols

### **4. U2R (User to Root)**
- **What:** Privilege escalation attempts
- **Examples:** Buffer overflow, rootkit installation
- **Detection:** Unusual system calls, privilege changes

---

## 🚀 MVP Implementation Plan

### **Phase 1: Foundation (Week 1-2)** ✅ CURRENT
- [x] Set up microservices architecture
- [x] Configure Docker containers
- [x] Create database schema
- [x] Build service skeletons
- [x] Implement health checks

### **Phase 2: ML Model (Week 3-4)** ⏳ NEXT
- [ ] Download NSL-KDD dataset
- [ ] Train Random Forest classifier
- [ ] Achieve >95% accuracy
- [ ] Save model (rf_model.pkl)
- [ ] Implement feature preprocessing

### **Phase 3: Core Services (Week 5-7)**
- [ ] ML Service: Prediction endpoints
- [ ] Ingestion Service: Data processing pipeline
- [ ] API Gateway: Complete CRUD operations
- [ ] Database: Query optimization

### **Phase 4: Dashboard (Week 8-9)**
- [ ] Real-time statistics display
- [ ] Alert management interface
- [ ] Threat visualization charts
- [ ] Historical data views

### **Phase 5: Testing & Deployment (Week 10)**
- [ ] Integration testing
- [ ] Load testing
- [ ] Security hardening
- [ ] Documentation
- [ ] Deploy to cloud (AWS/GCP)

---

## 📋 Prerequisites

- Docker (≥ 20.10)
- Docker Compose (≥ 2.0)
- Git

---

## ⚡ Quick Start

### 1. Clone & Setup
```bash
git clone <your-repo-url>
cd sonic

# Create environment file
cp .env.example .env

# Edit .env and add your secrets (keep defaults for development)
```

### 2. Start All Services
```bash
# Build and start
docker-compose up --build

# Or run in background
docker-compose up -d
```

### 3. Verify Services
```bash
# Check all services are running
docker-compose ps

# Test endpoints
curl http://localhost:8000/health  # ML Service
curl http://localhost:3000/health  # API Gateway
curl http://localhost:8080/health  # Ingestion Service
```

### 4. Access Dashboard
Open browser: **http://localhost**

---

## 🔧 Development Commands
```bash
# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Rebuild specific service
docker-compose up --build ml-service

# Access database
docker-compose exec postgres psql -U postgres -d threat_detector
```

---

## 📊 API Endpoints

### ML Service (Port 8000)
- `GET /health` - Health check
- `POST /predict` - Single prediction
- `POST /predict/batch` - Batch predictions

### API Gateway (Port 3000)
**All endpoints require `X-API-Key` header**

- `GET /api/v1/stats` - System statistics
- `GET /api/v1/alerts` - Recent alerts
- `GET /api/v1/threats` - Detected threats
- `POST /api/v1/analyze` - Analyze traffic

Example:
```bash
curl -H "X-API-Key: dev-api-key-12345" \
     http://localhost:3000/api/v1/stats
```

---

## 🗂️ Project Structure
```
sonic/
├── ml-service/           # Python/FastAPI - ML predictions
├── ingestion-service/    # Go - Data ingestion pipeline
├── api-gateway/          # Go - REST API
├── dashboard/            # React - Web interface
├── database/             # PostgreSQL schema
├── docker-compose.yaml   # Service orchestration
├── .env.example          # Environment template
└── README.md
```

---

## 🔐 Security Notes

**⚠️ This is a development setup. For production:**

- [ ] Change all default passwords
- [ ] Use strong API keys (32+ chars)
- [ ] Enable SSL/TLS
- [ ] Implement rate limiting
- [ ] Use secrets manager (AWS Secrets/Vault)
- [ ] Enable database encryption
- [ ] Set up proper logging/monitoring
- [ ] Configure firewall rules

---

## 🧪 ML Model Details

**Dataset:** NSL-KDD (Network Security Laboratory - Knowledge Discovery in Databases)

**Model Type:** Random Forest Classifier

**Features:** 41 network traffic features including:
- Connection duration
- Protocol type (TCP/UDP/ICMP)
- Service type (HTTP/FTP/SMTP)
- Bytes sent/received
- Error rates
- Connection counts

**Performance Target:** >95% accuracy

**Training:** Week 3-4 of implementation plan

---

## 🐛 Troubleshooting

### Services won't start
```bash
# Check logs
docker-compose logs ml-service

# Restart specific service
docker-compose restart ml-service
```

### Port already in use
```bash
# Find and kill process
lsof -i :8000  # Mac/Linux
```

### ML Model not loaded
The ML service starts without a model but can't make predictions. You need to:
1. Train the model (Phase 2)
2. Place `rf_model.pkl` in `ml-service/model/`
3. Restart ML service

---

## 📈 Current Status

**✅ Phase 1 Complete:** MVP skeleton ready with all services containerized

**⏳ Next Step:** Train ML model with NSL-KDD dataset

---

## 📝 License

Educational/Portfolio Project

---

## 🤝 Contributing

This is a learning project. Feedback and suggestions welcome via issues!

---

**Built with:** Go • Python • FastAPI • React • PostgreSQL • Redis • Docker