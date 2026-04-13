# Cloud-Based Zero-Day Attack Detection System

This project includes:
- A machine learning model for traffic classification
- A Flask backend API
- A React frontend dashboard
- AWS EC2 deployment instructions
- Optional AWS S3 request logging

## Project Structure

zero-day-project/
- backend/
  - app.py
  - train_model.py
  - model.pkl
  - requirements.txt
- frontend/
  - package.json
  - public/
    - index.html
  - src/
    - App.js
    - Dashboard.jsx
    - index.js
    - styles.css

## 1) Backend Setup (Local)

Open a terminal in backend and run:

```bash
pip install -r requirements.txt
python train_model.py
python app.py
```

Backend starts on:
- http://0.0.0.0:5000

Health check:
- GET /  -> Backend is running

Detection endpoint:
- POST /detect

Example request body:

```json
{
  "duration": 12,
  "src_bytes": 10000,
  "dst_bytes": 200
}
```

Example response:

```json
{
  "prediction": 1,
  "result": "Attack 🚨",
  "threat_score": 84.0
}
```

## 2) Frontend Setup (Local)

Open a terminal in frontend and run:

```bash
npm install
npm start
```

The app opens at:
- http://localhost:3000

### Configure Backend URL

In frontend/src/Dashboard.jsx, set:

```js
const DETECT_API_URL = "http://<EC2-IP>:5000/detect";
```

Or use environment variable in frontend/.env:

```env
REACT_APP_DETECT_URL=http://<EC2-IP>:5000/detect
```

## 3) AWS EC2 Deployment (Amazon Linux)

### Step A: Launch EC2
- Launch an Amazon Linux instance
- Allow inbound rules:
  - SSH (22)
  - Custom TCP (5000)

### Step B: Connect and Install Tools

```bash
sudo yum update -y
sudo yum install -y python3 python3-pip git
```

### Step C: Upload or Clone Backend

Option 1: Git clone

```bash
git clone <your-repository-url>
cd zero-day-project/backend
```

Option 2: Upload backend folder manually, then:

```bash
cd backend
```

### Step D: Install Dependencies and Run Backend

```bash
pip3 install -r requirements.txt
python3 train_model.py
python3 app.py
```

Backend URL:
- http://<EC2-IP>:5000

Test from your browser:
- http://<EC2-IP>:5000

## 4) Optional: AWS S3 Logging

Each detection request can be stored as a JSON file in S3.

### Prerequisites
- Create S3 bucket: zero-day-logs
- Attach IAM role to EC2 with permission to write to the bucket

### Run backend with S3 logging enabled

```bash
export ENABLE_S3_LOGGING=true
export S3_BUCKET_NAME=zero-day-logs
python3 app.py
```

Files will be written to bucket paths like:
- traffic-logs/YYYY/MM/DD/<timestamp>_<id>.json

## 5) Production Notes
- Use a process manager like systemd or supervisord to keep Flask running
- Use Nginx reverse proxy for production hardening
- Replace sample training data with real IDS datasets (KDD, NSL-KDD, CIC-IDS)

## 6) Quick End-to-End Test
1. Start backend on port 5000
2. Start frontend on port 3000
3. Enter traffic values in dashboard
4. Click Analyze Traffic
5. Verify prediction, threat score, popup alert, and history table updates
