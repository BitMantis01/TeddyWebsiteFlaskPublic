# 🐻 Project TEDDY Dashboard

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.3.3-green.svg)](https://flask.palletsprojects.com/)
[![AI](https://img.shields.io/badge/AI-Emotion%20Analysis-purple.svg)](#emotion-api)
[![License](https://img.shields.io/badge/License-All%20Rights%20Reserved-red.svg)](#license)

A comprehensive web dashboard for **Project TEDDY** - an AI-powered therapeutic teddy bear that provides emotional support and comfort to people of all ages. This Flask-based web application serves as the central management platform for TEDDY devices, offering user authentication, device pairing, real-time monitoring, AI-powered emotion analysis, and configuration management.

## 📚 Table of Contents

- [🐻 Project TEDDY Dashboard](#-project-teddy-dashboard)
  - [📚 Table of Contents](#-table-of-contents)
  - [✨ Features](#-features)
  - [🛠️ Technology Stack](#️-technology-stack)
  - [📋 Prerequisites](#-prerequisites)
  - [🚀 Quick Start](#-quick-start)
  - [⚙️ Configuration](#️-configuration)
  - [🧠 Emotion API Integration](#-emotion-api-integration)
  - [🗄️ Database Schema](#️-database-schema)
  - [📡 API Documentation](#-api-documentation)
  - [📁 Project Structure](#-project-structure)
  - [🔧 Development](#-development)
  - [🧪 Testing](#-testing)
  - [🚀 Deployment](#-deployment)
  - [🔒 Security](#-security)
  - [🎨 UI/UX Features](#-uiux-features)
  - [🤝 Contributing](#-contributing)
  - [👥 Team](#-team)
  - [📞 Support](#-support)
  - [📄 License](#-license)

## ✨ Features

### 🏠 **Landing Page**
- **Modern Design**: Responsive interface with smooth animations
- **Project Information**: Comprehensive details about Project TEDDY
- **Team Showcase**: Information about researchers and developers
- **Mobile Optimized**: Touch-friendly interface for all devices

### 🔐 **User Authentication System**
- **Secure Registration**: Email-based account creation with strong password requirements
- **Login Management**: Persistent sessions with "Remember Me" functionality
- **Profile Completion**: Guided user onboarding process
- **Session Security**: Automatic token cleanup and secure cookie handling
- **Admin System**: Comprehensive admin panel for user management

### 📊 **Dashboard Interface**
- **Profile Management**: Complete user profile editing capabilities
- **Device Pairing**: Simple 6-digit code pairing system for TEDDY devices
- **Real-time Monitoring**: Live battery status and connection tracking
- **Target Configuration**: Customizable settings for different user demographics
- **Activity Logs**: Historical data tracking and visualization
- **Role-Based Access**: Separate dashboards for regular users and administrators

### 🧠 **AI-Powered Emotion Analysis**
- **Text Emotion Analysis**: Analyzes text input for emotional keywords and sentiment
- **Image Emotion Recognition**: Facial emotion detection from uploaded images (with ML libraries)
- **Audio Emotion Analysis**: Speech-to-text transcription with emotion analysis (with ML libraries)
- **Real-time Processing**: Instant emotion analysis through web interface
- **Multi-modal Support**: Combines text, image, and audio analysis
- **Confidence Scoring**: Provides confidence levels for emotion predictions

### � **Administrative Features**
- **User Management**: View, edit, promote/demote, and delete users
- **System Statistics**: Comprehensive analytics and usage metrics
- **Device Monitoring**: Monitor all TEDDY devices across the platform
- **Activity Logs**: Track user actions and system events
- **Role-Based Permissions**: Secure admin-only access to management features

### �🔌 **API Endpoints**
- **Data Reception**: `/api/receive-data` - Receive telemetry from TEDDY devices
- **Configuration Broadcast**: `/api/broadcast-teddy` - Send settings to devices
- **Emotion Analysis**: `/api/emotion/*` - AI-powered emotion analysis endpoints
- **Authentication**: Secure API key-based authentication
- **Error Handling**: Comprehensive error responses and logging

## 🛠️ Technology Stack

| Component | Technology | Version |
|-----------|------------|---------|
| **Backend Framework** | Flask | 2.3.3 |
| **Database** | SQLite | Built-in |
| **Frontend Framework** | Bootstrap | 5.x |
| **Styling** | CSS3 | Latest |
| **Scripting** | JavaScript (ES6+) | Latest |
| **Icons** | Font Awesome | Latest |
| **Fonts** | Google Fonts (Poppins) | Latest |
| **Security** | Cloudflare Turnstile | Latest |

## 📋 Prerequisites

Before you begin, ensure you have the following installed:

- **Python 3.8+** ([Download](https://python.org/downloads/))
- **pip** (Python package manager - included with Python)
- **Git** ([Download](https://git-scm.com/downloads)) - for cloning the repository

## 🚀 Installation & Setup

### Basic Installation (Text Analysis Only)

#### 1. **Clone the Repository**
```bash
git clone https://github.com/BitMantis01/TeddyWebsiteFlaskPublic.git
cd TeddyWebsiteFlask
```

#### 2. **Set Up Virtual Environment** (Recommended)
```bash
# Create virtual environment
python -m venv teddy-env

# Activate virtual environment
# On Windows:
teddy-env\Scripts\activate
# On macOS/Linux:
source teddy-env/bin/activate
```

#### 3. **Install Dependencies**
```bash
pip install -r requirements.txt
```

#### 4. **Configure the Application**
```bash
# Copy the configuration template
cp config.json.template config.json
```

Edit `config.json` with your settings:
```json
{
  "secret_key": "your-secure-secret-key-here",
  "database_path": "teddy.db",
  "api_key": "your-api-key-for-devices",
  "emotion_api": {
    "enabled": true,
    "whisper_model": "base",
    "whisper_device": "cpu",
    "fer_mtcnn": false
  }
}
```

#### 5. **Initialize Database**
```bash
python -c "from app import init_db; init_db()"
```

#### 6. **Run the Application**
```bash
python app.py
```

Access the application at: `http://localhost:5000`

### Full ML Installation (Image + Audio Analysis)

For complete emotion analysis functionality, install the ML dependencies:

#### CPU-Only Installation (Recommended)
```bash
# Install PyTorch CPU version
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu

# Install ML libraries
pip install numpy opencv-python fer faster-whisper
```

#### GPU Installation (Advanced Users)
```bash
# For NVIDIA GPU support
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118

# Install ML libraries
pip install numpy opencv-python fer faster-whisper
```

**Note:** ML libraries are large (2-4GB) and require significant computational resources.

### Configuration Details

#### Configuration Options:
- **secret_key**: Flask session encryption key (generate securely for production)
- **database_path**: SQLite database file location
- **api_key**: Authentication key for device API access
- **emotion_api.enabled**: Enable/disable emotion API features
- **emotion_api.whisper_model**: AI model size (`tiny`, `base`, `small`, `medium`, `large`)
- **emotion_api.whisper_device**: Processing device (`cpu`, `auto`)
- **emotion_api.fer_mtcnn**: Advanced face detection (higher accuracy, slower processing)

### Environment Variables (Optional)
```bash
# Set environment variables for production
export FLASK_ENV=production
export FLASK_APP=app.py
export SECRET_KEY=your-production-secret-key
```

## 🧠 AI-Powered Emotion Analysis

### Overview

The TEDDY Emotion API provides AI-powered emotion analysis capabilities for text, images, and audio. This integration allows your TEDDY dashboard to analyze emotional content and provide insights.

### Emotion Analysis Features

#### 🧠 **Text Emotion Analysis**
- Analyzes text input for emotional keywords
- Supports multiple emotion types: happiness, sadness, anger, fear, surprise, neutral, disgust, trust, anticipation, farewell
- Keyword-based classification with confidence scoring
- Real-time analysis through web interface

#### 📸 **Image Emotion Analysis** (Requires ML Libraries)
- Facial emotion recognition using FER (Facial Emotion Recognition)
- Detects emotions from uploaded PNG images
- Multi-face detection and emotion aggregation
- Confidence scores for each detected emotion

#### 🎵 **Audio Emotion Analysis** (Requires ML Libraries)
- Speech-to-text transcription using Whisper
- Emotion analysis from transcribed text
- Supports MP3 audio files
- Combines transcription confidence with emotion analysis

### Web Interface

#### Dashboard Integration
- New "AI Features" section added to the dashboard
- Direct access to emotion analysis tools
- API documentation modal

#### Emotion Analysis Page
Access via: `http://localhost:5000/emotion-analysis`

Features:
- Upload and analyze images
- Upload and analyze MP3 audio files
- Type or paste text for analysis
- Real-time results with emotion scores
- Keyword highlighting
- Progress indicators

### Emotion Categories

The API recognizes these emotions:

1. **Primary Emotions:**
   - Happiness
   - Sadness
   - Anger
   - Fear
   - Surprise
   - Disgust
   - Neutral

2. **Extended Emotions:**
   - Trust
   - Anticipation
   - Farewell

### Mock Mode

When ML libraries are not installed, the API operates in "mock mode":
- Text analysis works normally (keyword-based)
- Image analysis returns mock emotional responses
- Audio analysis returns mock transcriptions
- All responses include a `"mock": true` flag

### Performance Considerations

#### Resource Usage:
- **Text Analysis:** Minimal CPU/memory usage
- **Image Analysis:** Moderate CPU usage, ~500MB-1GB RAM
- **Audio Analysis:** High CPU usage, ~1-2GB RAM

#### Optimization Tips:
- Use smaller Whisper models (`tiny` or `base`) for faster processing
- Disable MTCNN face detection unless needed for accuracy
- Consider GPU acceleration for production deployments
- Implement caching for repeated analyses
Open your web browser and navigate to:
```
http://localhost:5000
```

## ⚙️ Configuration

The application uses a `config.json` file for all configuration settings. Follow these steps to configure your installation:

## 📚 API Documentation & Usage

All API endpoints require authentication via the `X-API-Key` header.

### Authentication
```bash
# Include API key in all requests
X-API-Key: your-api-key-from-config
```

### Core API Endpoints

#### Health Check
```http
GET /api/emotion/health
```

**Description:** Returns API status and ML library availability.

**Response:**
```json
{
    "status": "healthy",
    "ml_libraries": {
        "fer_available": true,
        "whisper_available": true
    },
    "config": {
        "whisper_model": "base",
        "whisper_device": "cpu"
    }
}
```

#### Device Data Reception
```http
POST /api/receive-data
Content-Type: application/json
X-API-Key: your-api-key
```

**Description:** Receive telemetry data from TEDDY devices.

**Request Body:**
```json
{
    "device_id": "TEDDY001",
    "battery_level": 85,
    "temperature": 23.5,
    "activity_level": "moderate",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

**Response:**
```json
{
    "status": "success",
    "message": "Data received successfully",
    "device_id": "TEDDY001"
}
```

#### Configuration Broadcast
```http
POST /api/broadcast-teddy
Content-Type: application/json
X-API-Key: your-api-key
```

**Description:** Send configuration settings to TEDDY devices.

**Request Body:**
```json
{
    "target_devices": ["TEDDY001", "TEDDY002"],
    "settings": {
        "comfort_mode": true,
        "response_sensitivity": "high",
        "led_brightness": 80
    }
}
```

### Emotion Analysis API Endpoints

#### Text Analysis
```http
POST /api/emotion/analyze/text
Content-Type: application/json
X-API-Key: your-api-key
```

**Request Body:**
```json
{
    "text": "I'm feeling happy today!"
}
```

**Response:**
```json
{
    "emotion": "happiness",
    "confidence": 0.85,
    "keywords": ["happy"],
    "all_scores": {
        "happiness": 0.85,
        "sadness": 0.05,
        "neutral": 0.10
    }
}
```

#### Image Analysis
```http
POST /api/emotion/analyze/image
Content-Type: multipart/form-data
X-API-Key: your-api-key
```

**Request:** Upload PNG image file

**Response:**
```json
{
    "emotion": "happiness",
    "confidence": 0.78,
    "faces_detected": 1,
    "all_scores": {
        "happiness": 0.78,
        "surprise": 0.15,
        "neutral": 0.07
    },
    "mock": false
}
```

#### Audio Analysis
```http
POST /api/emotion/analyze/audio
Content-Type: multipart/form-data
X-API-Key: your-api-key
```

**Request:** Upload MP3 audio file

**Response:**
```json
{
    "emotion": "happiness",
    "confidence": 0.72,
    "transcription": "I am really excited about this!",
    "transcription_confidence": 0.95,
    "keywords": ["excited"],
    "mock": false
}
```

### API Usage Examples

#### JavaScript (Web Interface)
```javascript
// Text emotion analysis
const analyzeText = async (text) => {
    const response = await fetch('/api/emotion/analyze/text', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-API-Key': 'your-api-key'
        },
        body: JSON.stringify({ text: text })
    });
    
    const result = await response.json();
    console.log(`Emotion: ${result.emotion}, Confidence: ${result.confidence}`);
    return result;
};

// Image emotion analysis
const analyzeImage = async (imageFile) => {
    const formData = new FormData();
    formData.append('file', imageFile);
    
    const response = await fetch('/api/emotion/analyze/image', {
        method: 'POST',
        headers: {
            'X-API-Key': 'your-api-key'
        },
        body: formData
    });
    
    return await response.json();
};

// Device data submission
const sendDeviceData = async (deviceData) => {
    const response = await fetch('/api/receive-data', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-API-Key': 'your-api-key'
        },
        body: JSON.stringify(deviceData)
    });
    
    return await response.json();
};
```

#### Python (Backend Integration)
```python
import requests
import json

# Text emotion analysis
def analyze_text_emotion(text, api_key):
    response = requests.post(
        'http://localhost:5000/api/emotion/analyze/text',
        headers={'X-API-Key': api_key},
        json={'text': text}
    )
    return response.json()

# Device data submission
def send_device_data(device_data, api_key):
    response = requests.post(
        'http://localhost:5000/api/receive-data',
        headers={
            'X-API-Key': api_key,
            'Content-Type': 'application/json'
        },
        json=device_data
    )
    return response.json()

# Image emotion analysis
def analyze_image_emotion(image_path, api_key):
    with open(image_path, 'rb') as image_file:
        files = {'file': image_file}
        headers = {'X-API-Key': api_key}
        response = requests.post(
            'http://localhost:5000/api/emotion/analyze/image',
            headers=headers,
            files=files
        )
    return response.json()

# Example usage
api_key = "your-api-key"
result = analyze_text_emotion("I am very excited!", api_key)
print(f"Detected emotion: {result['emotion']}")
```

#### curl (Command Line)
```bash
# Text emotion analysis
curl -X POST \
  http://localhost:5000/api/emotion/analyze/text \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"text": "I am feeling great today!"}'

# Device data submission
curl -X POST \
  http://localhost:5000/api/receive-data \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "device_id": "TEDDY001",
    "battery_level": 85,
    "temperature": 23.5,
    "activity_level": "moderate"
  }'

# Image emotion analysis
curl -X POST \
  http://localhost:5000/api/emotion/analyze/image \
  -H "X-API-Key: your-api-key" \
  -F "file=@path/to/image.png"

# Audio emotion analysis
curl -X POST \
  http://localhost:5000/api/emotion/analyze/audio \
  -H "X-API-Key: your-api-key" \
  -F "file=@path/to/audio.mp3"
```

### Error Handling

#### Common HTTP Status Codes
- `200`: Success
- `400`: Bad Request (invalid input)
- `401`: Unauthorized (missing/invalid API key)
- `413`: Payload Too Large (file size exceeded)
- `415`: Unsupported Media Type (wrong file format)
- `500`: Internal Server Error

#### Error Response Format
```json
{
    "error": "Invalid file format",
    "details": "Only PNG images are supported",
    "status_code": 415
}
```

### Rate Limiting & Best Practices

#### Recommendations:
1. **File Size Limits:**
   - Images: Maximum 10MB
   - Audio: Maximum 25MB
   - Text: Maximum 10,000 characters

2. **Performance Optimization:**
   - Cache results for repeated analyses
   - Use smaller Whisper models for faster audio processing
   - Process files sequentially to avoid resource conflicts

3. **Error Handling:**
   - Always check response status codes
   - Implement retry logic with exponential backoff
   - Validate file formats before uploading

4. **Security:**
   - Store API keys securely
   - Use HTTPS in production
   - Validate all user inputs
## 🧪 Testing & Validation

### Running Tests

#### Test the Emotion API
```bash
python test_emotion_api.py
```

This will test:
- API health status
- Text emotion analysis
- Various emotion types
- Error handling

#### Test Basic Functionality
```bash
# Test the application manually by:
# 1. Starting the server
python app.py

# 2. Open browser and test:
# - Registration: http://localhost:5000/register
# - Login: http://localhost:5000/login
# - Dashboard: http://localhost:5000/dashboard
# - Emotion Analysis: http://localhost:5000/emotion-analysis
```

### Validation Checklist

#### ✅ Core Features
- [ ] User registration and login
- [ ] Profile management
- [ ] Device pairing with 6-digit codes
- [ ] Dashboard functionality
- [ ] API endpoints responding correctly

#### ✅ Emotion Analysis
- [ ] Text analysis working
- [ ] Image upload and analysis (if ML libraries installed)
- [ ] Audio upload and analysis (if ML libraries installed)
- [ ] Mock mode working when ML libraries not available

#### ✅ Admin Features
- [ ] Admin user creation
- [ ] User management interface
- [ ] System statistics
- [ ] Role-based access control

#### ✅ Security
- [ ] API key authentication
- [ ] Session management
- [ ] Input validation
- [ ] SQL injection protection

## 🔧 Configuration & Deployment

### Configuration Setup

1. **Copy the template:**
   ```bash
   cp config.json.template config.json
   ```

2. **Edit the configuration:**
   ```json
   {
       "secret_key": "your-flask-secret-key-here",
       "database_path": "teddy.db", 
       "api_key": "your-api-key-here",
       "website_url": "your-domain.com",
       "manager_name": "Your Name",
       "manager_url": "your-manager-site.com",
       "emotion_api": {
           "enabled": true,
           "whisper_model": "base",
           "whisper_device": "cpu",
           "fer_mtcnn": false
       },
       "turnstile": {
           "site_key": "your-turnstile-site-key",
           "secret_key": "your-turnstile-secret-key"
       }
   }
   ```

### Configuration Parameters

| Parameter | Description | Required | Example |
|-----------|-------------|----------|---------|
| `secret_key` | Flask session secret key | ✅ | `"randomly-generated-secret-key"` |
| `database_path` | SQLite database file path | ✅ | `"teddy.db"` |
| `api_key` | API authentication key | ✅ | `"your-api-key-here"` |
| `website_url` | Your website domain | ✅ | `"your-domain.com"` |
| `manager_name` | Manager/Contact name | ✅ | `"Your Name"` |
| `manager_url` | Manager contact URL | ✅ | `"your-site.com"` |
| `emotion_api.enabled` | Enable emotion API features | ✅ | `true` |
| `emotion_api.whisper_model` | AI model size | ✅ | `"base"` |
| `turnstile.site_key` | Cloudflare Turnstile site key | ✅ | `"0x4AAAAAAAA..."` |
| `turnstile.secret_key` | Cloudflare Turnstile secret key | ✅ | `"0x4AAAAAAAA..."` |

### Security Keys Generation

```bash
# Generate a secure secret key
python -c "import secrets; print(secrets.token_hex(32))"

# Generate a secure API key
python -c "import secrets; print(secrets.token_hex(32))"
```

### Cloudflare Turnstile Setup

1. Visit [Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/)
2. Create a new site
3. Get your site key and secret key
4. Add them to your `config.json`

> ⚠️ **Security Warning**: Never commit your actual `config.json` file to version control. It contains sensitive credentials that should be kept private.

## 🗄️ Database Schema

The application uses SQLite as its database backend with the following schema:

### **Users Table** (`users`)
Stores user account information and profiles.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY, AUTOINCREMENT | Unique user identifier |
| `email` | TEXT | UNIQUE, NOT NULL | User's email address |
| `password_hash` | TEXT | NOT NULL | SHA-256 hashed password |
| `first_name` | TEXT | | User's first name |
| `last_name` | TEXT | | User's last name |
| `birthday` | TEXT | | User's date of birth (YYYY-MM-DD) |
| `country` | TEXT | | User's country |
| `contact_number` | TEXT | | User's phone number |
| `is_admin` | INTEGER | DEFAULT 0 | Admin status (0=user, 1=admin) |
| `created_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Account creation date |

### **TEDDY Devices Table** (`teddy_devices`)
Manages TEDDY device registrations and pairings.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY, AUTOINCREMENT | Unique device identifier |
| `teddy_code` | TEXT | UNIQUE, NOT NULL | 6-digit device code |
| `user_id` | INTEGER | FOREIGN KEY → users(id) | Owner of the device |
| `device_name` | TEXT | | Custom device name |
| `battery_level` | INTEGER | | Current battery percentage |
| `target_first_name` | TEXT | | Target user's first name |
| `target_last_name` | TEXT | | Target user's last name |
| `target_age` | INTEGER | | Target user's age |
| `target_gender` | TEXT | | Target user's gender |
| `target_relationship` | TEXT | | Relationship to target user |
| `is_active` | INTEGER | DEFAULT 1 | Device status (0=inactive, 1=active) |
| `last_seen` | TIMESTAMP | | Last device communication |
| `created_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Device registration date |

### **TEDDY Logs Table** (`teddy_logs`)
Historical data and activity tracking.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY, AUTOINCREMENT | Unique log identifier |
| `device_id` | INTEGER | FOREIGN KEY → teddy_devices(id) | Related device |
| `user_id` | INTEGER | FOREIGN KEY → users(id) | Related user |
| `activity_type` | TEXT | NOT NULL | Type of activity logged |
| `activity_data` | TEXT | | JSON data for the activity |
| `battery_level` | INTEGER | | Battery level at time of log |
| `temperature` | REAL | | Device temperature |
| `timestamp` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | When activity occurred |

### Database Relationships

```
users (1) ←→ (many) teddy_devices
teddy_devices (1) ←→ (many) teddy_logs
users (1) ←→ (many) teddy_logs
```

### Index Optimization

The following indexes are created for performance:

```sql
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_teddy_devices_code ON teddy_devices(teddy_code);
CREATE INDEX idx_teddy_devices_user ON teddy_devices(user_id);
CREATE INDEX idx_teddy_logs_device ON teddy_logs(device_id);
CREATE INDEX idx_teddy_logs_user ON teddy_logs(user_id);
CREATE INDEX idx_teddy_logs_timestamp ON teddy_logs(timestamp);
```

## 🚀 Deployment

### Development Deployment
```bash
# Simple development server
python app.py
```

### Production Deployment

#### Using Gunicorn (Recommended)
```bash
# Install Gunicorn
pip install gunicorn

# Run with Gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

#### Using Docker
```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 5000

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
```

#### Environment Variables for Production
```bash
export FLASK_ENV=production
export SECRET_KEY=your-production-secret-key
export DATABASE_URL=sqlite:///path/to/production.db
```

### Reverse Proxy Setup (Nginx)
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static {
        alias /path/to/app/static;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY, AUTOINCREMENT | Unique device identifier |
| `teddy_code` | TEXT | UNIQUE, NOT NULL | 6-digit device code |
| `user_id` | INTEGER | FOREIGN KEY | Associated user ID |
| `battery_level` | INTEGER | DEFAULT 0 | Current battery percentage |
| `target_user` | TEXT | DEFAULT 'Children' | Target demographic setting |
| `last_updated` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Last data update time |

### **TEDDY Logs Table** (`teddy_logs`)
Historical data tracking for analytics and monitoring.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY, AUTOINCREMENT | Unique log entry identifier |
| `teddy_code` | TEXT | NOT NULL, FOREIGN KEY | Device code reference |
| `battery_level` | INTEGER | | Battery level at time of log |
| `timestamp` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Log entry timestamp |

### **Remember Tokens Table** (`remember_tokens`)
Manages "Remember Me" login functionality.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY, AUTOINCREMENT | Unique token identifier |
| `user_id` | INTEGER | NOT NULL, FOREIGN KEY | Associated user ID |
| `token` | TEXT | UNIQUE, NOT NULL | Secure remember token |
| `expires_at` | TIMESTAMP | NOT NULL | Token expiration time |
| `created_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Token creation time |

## 📡 API Documentation

The TEDDY Dashboard provides RESTful API endpoints for device communication and data exchange.

### **Authentication**

All API endpoints require authentication using an API key passed in the request headers:

```http
X-API-Key: your-api-key-here
```

Alternative authentication format:
```http
## 🔧 Troubleshooting

### Common Issues & Solutions

#### Installation Issues

**Problem:** `ImportError: No module named 'fer'`
```bash
# Solution: Install ML dependencies
pip install fer opencv-python numpy
```

**Problem:** `torch not found`
```bash
# Solution: Install PyTorch
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu
```

**Problem:** Database initialization fails
```bash
# Solution: Initialize database manually
python -c "from app import init_db; init_db()"
```

#### Runtime Issues

**Problem:** API returns 401 Unauthorized
- **Cause:** Missing or incorrect API key
- **Solution:** Check `X-API-Key` header matches `config.json`

**Problem:** Slow audio processing
- **Cause:** Large Whisper model or long audio files
- **Solution:** Use smaller model (`tiny` instead of `base`) or shorter audio

**Problem:** Image analysis fails
- **Cause:** Unsupported file format or corrupted image
- **Solution:** Use PNG format, check file integrity

**Problem:** Memory issues during ML processing
- **Cause:** Large models loading into memory
- **Solution:** Use CPU-only PyTorch, restart application periodically

#### Configuration Issues

**Problem:** Turnstile validation fails
- **Cause:** Incorrect site/secret keys
- **Solution:** Verify keys in Cloudflare dashboard

**Problem:** Admin features not working
- **Cause:** User not marked as admin in database
- **Solution:** Update user in database: `UPDATE users SET is_admin=1 WHERE email='admin@example.com'`

### Debug Mode

Enable debug mode for detailed error messages:

```python
# In app.py, change:
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
```

### Logging

Check application logs for detailed error information:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Performance Optimization

#### For Large Deployments:
1. **Database Optimization:**
   - Use PostgreSQL instead of SQLite
   - Implement connection pooling
   - Add proper indexes

2. **ML Processing:**
   - Use GPU acceleration
   - Implement processing queues
   - Cache model results

3. **Web Server:**
   - Use production WSGI server (Gunicorn)
   - Implement load balancing
   - Add caching layers (Redis)

## 🤝 Contributing

We welcome contributions to improve Project TEDDY! Here's how you can help:

### Development Setup

1. **Fork the Repository**
   ```bash
   git clone https://github.com/yourusername/TeddyWebsiteFlask.git
   cd TeddyWebsiteFlask
   ```

2. **Create Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Set Up Development Environment**
   ```bash
   python -m venv dev-env
   source dev-env/bin/activate  # or dev-env\Scripts\activate on Windows
   pip install -r requirements.txt
   ```

4. **Make Changes and Test**
   ```bash
   python test_emotion_api.py
   python app.py  # Test manually
   ```

5. **Submit Pull Request**
   ```bash
   git add .
   git commit -m "Add your feature description"
   git push origin feature/your-feature-name
   ```

### Contribution Guidelines

#### Code Style:
- Follow PEP 8 for Python code
- Use meaningful variable and function names
- Add docstrings for functions and classes
- Include type hints where appropriate

#### Testing:
- Test all new features thoroughly
- Include unit tests for new functions
- Verify compatibility with existing features
- Test both with and without ML libraries

#### Documentation:
- Update README.md for new features
- Add inline comments for complex logic
- Update API documentation for new endpoints
- Include usage examples

### Priority Areas for Contribution

1. **Frontend Improvements:**
   - Enhanced UI/UX design
   - Better mobile responsiveness
   - Accessibility improvements
   - Progressive Web App features

2. **Backend Features:**
   - Additional emotion analysis models
   - Real-time device communication
   - Advanced analytics and reporting
   - Multi-language support

3. **Security Enhancements:**
   - OAuth integration
   - Two-factor authentication
   - Rate limiting
   - Input sanitization improvements

4. **Performance Optimizations:**
   - Database query optimization
   - Caching strategies
   - Async processing
   - Resource management

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Flask Community** - For the excellent web framework
- **Bootstrap Team** - For the responsive CSS framework
- **OpenAI** - For Whisper speech recognition model
- **FER Contributors** - For facial emotion recognition library
- **Cloudflare** - For Turnstile CAPTCHA service

## 📞 Support

For support, questions, or feature requests:

1. **GitHub Issues:** [Create an issue](https://github.com/BitMantis01/TeddyWebsiteFlaskPublic/issues)
2. **Documentation:** Check this README and inline code comments
3. **Testing:** Run `python test_emotion_api.py` to verify setup
4. **Community:** Join discussions in GitHub Discussions

## 🔄 Changelog

### v2.0.0 (Current)
- ✅ Added comprehensive admin system
- ✅ Integrated AI-powered emotion analysis
- ✅ Enhanced mobile responsiveness
- ✅ Improved dark mode support
- ✅ Added role-based access control
- ✅ Expanded API documentation

### v1.0.0
- ✅ Initial release with basic dashboard
- ✅ User authentication system
- ✅ Device pairing functionality
- ✅ Basic API endpoints

---

**Project TEDDY Dashboard** - Connecting hearts through technology 💙

*Built with ❤️ for therapeutic innovation and emotional well-being*
    "message": "Invalid teddy code"
}
```

**Status Codes:**
- `200 OK` - Data processed successfully
- `400 Bad Request` - Invalid request format or parameters
- `401 Unauthorized` - Missing or invalid API key
- `500 Internal Server Error` - Server processing error

### **📡 Broadcast Configuration Endpoint**

**Endpoint:** `GET /api/broadcast-teddy`

**Description:** Returns target user configuration for a specific TEDDY device.

**Request Headers:**
```http
X-API-Key: your-api-key-here
```

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `teddycode` | string | ✅ | 6-digit device identifier |

**Example Request:**
```http
GET /api/broadcast-teddy?teddycode=123456
```

**Response (Success):**
```json
{
    "success": true,
    "teddycode": "123456",
    "target_user": "Children"
}
```

**Response (Device Not Found):**
```json
{
    "success": false,
    "message": "Teddy not found or not paired"
}
```

**Status Codes:**
- `200 OK` - Configuration retrieved successfully
- `400 Bad Request` - Invalid teddy code format
- `401 Unauthorized` - Missing or invalid API key
- `404 Not Found` - Device not found or not paired
- `500 Internal Server Error` - Server processing error

### **Target User Options**

The following target user categories are supported:
- `Children` - Ages 3-12
- `Teens` - Ages 13-19
- `Adults` - Ages 20-64
- `Elderly` - Ages 65+
- `Autistic` - Autism spectrum support
- `Anxious` - Anxiety support
- `Patients` - Medical/therapeutic use

## 📁 Project Structure

```
TeddyWebsiteFlask/
├── 📄 app.py                      # Main Flask application
├── ⚙️ config.json                 # Configuration file (excluded from git)
├── 📋 config.json.template        # Configuration template
├── 📝 requirements.txt            # Python dependencies
├── 📖 README.md                   # This documentation
├── 🗄️ teddy.db                    # SQLite database (auto-created)
├── 🚫 .gitignore                  # Git ignore rules
├── 📁 static/                     # Static web assets
│   ├── 🎨 css/
│   │   └── style.css              # Main stylesheet
│   ├── ⚡ js/
│   │   └── main.js                # JavaScript functionality
│   └── 🖼️ images/
│       ├── favicon.ico            # Website favicon
│       └── logo.webp              # Project logo
├── 📁 templates/                  # Jinja2 HTML templates
│   ├── base.html                  # Base template layout
│   ├── landing.html               # Homepage
│   ├── login.html                 # User login page
│   ├── register.html              # User registration page
│   ├── complete_profile.html      # Profile completion
│   ├── dashboard.html             # Main dashboard
│   └── edit_profile.html          # Profile editing
├── 📁 test/                       # Testing scripts
│   ├── test_api.py                # Basic API testing
│   └── test_api_advanced.py       # Comprehensive API tests
└── 📁 temp/                       # Temporary files directory
```

## 🔧 Development

### **Development Environment Setup**

1. **Install development dependencies:**
   ```bash
   pip install -r requirements.txt
   pip install pytest flask-testing  # For testing
   ```

2. **Enable debug mode:**
   ```python
   # In app.py, ensure debug mode is enabled for development
   if __name__ == '__main__':
       app.run(debug=True, host='0.0.0.0', port=5000)
   ```

3. **Database management:**
   ```bash
   # Reset database (deletes all data)
   rm teddy.db
   python app.py  # Will recreate database
   ```

### **Code Style Guidelines**

- **Python**: Follow PEP 8 style guidelines
- **HTML**: Use semantic HTML5 elements
- **CSS**: Use BEM naming convention where applicable
- **JavaScript**: Use ES6+ features with proper error handling

### **Adding New Features**

1. **Backend (Flask routes):**
   - Add new routes in `app.py`
   - Follow existing error handling patterns
   - Validate all user inputs
   - Use consistent response formats

2. **Frontend (Templates):**
   - Extend `base.html` for consistency
   - Use Bootstrap classes for styling
   - Include proper ARIA labels for accessibility

3. **Database changes:**
   - Update the `init_db()` function
   - Consider migration strategies for existing data

## 🧪 Testing

The project includes comprehensive testing scripts to ensure reliability and functionality.

### **Available Test Scripts**

1. **Basic API Testing** (`test_api.py`)
   - Continuous testing of API endpoints
   - Multiple device simulation
   - Real-time monitoring

2. **Advanced API Testing** (`test_api_advanced.py`)
   - Comprehensive test coverage
   - Error condition testing
   - Authentication validation

### **Running Tests**

```bash
# Basic continuous testing
python test_api.py

# Advanced comprehensive testing
python test_api_advanced.py

# Run with custom server URL
python test_api_advanced.py http://your-server.com
```

### **Test Coverage**

- ✅ API authentication
- ✅ Data reception endpoints
- ✅ Configuration broadcast
- ✅ Input validation
- ✅ Error handling
- ✅ Database operations

## 🚀 Deployment

### **Production Deployment Checklist**

#### **Security Configuration**
- [ ] Generate secure secret keys
- [ ] Configure HTTPS certificates
- [ ] Set `secure=True` for cookies
- [ ] Enable CSRF protection
- [ ] Configure proper CORS headers

#### **Server Configuration**
- [ ] Use a production WSGI server (Gunicorn, uWSGI)
- [ ] Configure reverse proxy (Nginx, Apache)
- [ ] Set up SSL/TLS certificates
- [ ] Configure firewall rules

#### **Database**
- [ ] Consider migration to PostgreSQL for production
- [ ] Implement regular backups
- [ ] Configure connection pooling

### **Example Production Setup**

#### **Using Gunicorn + Nginx**

1. **Install Gunicorn:**
   ```bash
   pip install gunicorn
   ```

2. **Run with Gunicorn:**
   ```bash
   gunicorn -w 4 -b 127.0.0.1:5000 app:app
   ```

3. **Nginx Configuration:**
   ```nginx
   server {
       listen 80;
       server_name your-domain.com;
       
       location / {
           proxy_pass http://127.0.0.1:5000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       }
   }
   ```

### **Environment Variables**

Consider using environment variables for sensitive configuration in production:

```bash
export FLASK_SECRET_KEY="your-secret-key"
export TEDDY_API_KEY="your-api-key"
export TURNSTILE_SECRET="your-turnstile-secret"
```

## 🔒 Security

### **Implemented Security Features**

| Feature | Implementation | Status |
|---------|----------------|--------|
| **Password Hashing** | SHA-256 with salt | ✅ Implemented |
| **Session Management** | Flask sessions with secure cookies | ✅ Implemented |
| **Input Validation** | Comprehensive validation functions | ✅ Implemented |
| **SQL Injection Protection** | Parameterized queries | ✅ Implemented |
| **XSS Protection** | HTML escaping | ✅ Implemented |
| **CSRF Protection** | Token-based validation | ⚠️ Partially implemented |
| **Rate Limiting** | IP-based login attempts | ✅ Implemented |
| **API Authentication** | Key-based access control | ✅ Implemented |

### **Security Recommendations**

#### **For Production**
- Use HTTPS everywhere
- Implement proper CSRF protection
- Consider bcrypt for password hashing
- Set up proper logging and monitoring
- Regular security audits
- Keep dependencies updated

#### **Password Requirements**
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

## 🎨 UI/UX Features

### **🎨 Design System**
- **Color Scheme**: Modern purple and blue gradient theme
- **Typography**: Poppins font family for readability
- **Icons**: Font Awesome for consistent iconography
- **Spacing**: Bootstrap 5 utility classes for consistent spacing

### **📱 Responsive Design**
- **Mobile-First**: Optimized for touch interfaces
- **Breakpoints**: Full responsive grid system
- **Touch-Friendly**: Large click targets and touch gestures
- **Cross-Browser**: Compatible with all modern browsers

### **⚡ Performance Optimizations**
- **Lazy Loading**: Images and animations load on demand
- **Minified Assets**: Compressed CSS and JavaScript
- **Efficient Queries**: Optimized database operations
- **Caching**: Appropriate cache headers for static assets

### **♿ Accessibility Features**
- **ARIA Labels**: Screen reader compatibility
- **Keyboard Navigation**: Full keyboard accessibility
- **Color Contrast**: WCAG compliant color ratios
- **Focus Indicators**: Clear focus states for all interactive elements

## 🤝 Contributing

We welcome contributions to improve the Project TEDDY Dashboard! Here's how you can help:

### **Getting Started**

1. **Fork the repository**
2. **Create a feature branch:**
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Make your changes**
4. **Test thoroughly**
5. **Commit your changes:**
   ```bash
   git commit -m 'Add amazing feature'
   ```
6. **Push to your branch:**
   ```bash
   git push origin feature/amazing-feature
   ```
7. **Open a Pull Request**

### **Contribution Guidelines**

- Follow the existing code style
- Add tests for new features
- Update documentation as needed
- Ensure all tests pass
- Write clear commit messages

### **Areas for Contribution**

- 🐛 Bug fixes
- ✨ New features
- 📚 Documentation improvements
- 🎨 UI/UX enhancements
- 🔒 Security improvements
- ⚡ Performance optimizations

## 👥 Team

### **🎓 Research Team - STEM 1209**

| Role | Name |
|------|------|
| 🧠 **Researcher** | Shanealei Salve L. Sta. Maria |
| 🧠 **Researcher** | Khasheica Kleane P. Lacap |
| 🧠 **Researcher** | Felix Andrei M. Camillon |
| 🧠 **Researcher** | Matthew Gabriel M. Generoso |
| 🧠 **Researcher** | Mark James D. Lazaro |
| 🧠 **Researcher** | Alson John D. Milante |

### **👨‍🏫 Academic Supervision**
- **Research Adviser:** Hazel Jhoy C. Del Mundo

### **💻 Technical Management**
- **Website Manager:** John Reyn Santino

### **🏫 Institution**
This project is developed as part of the STEM 1209 research program, focusing on innovative therapeutic technologies and human-computer interaction.

## 📞 Support

### **🆘 Getting Help**

If you encounter issues or have questions:

1. **📖 Check the Documentation** - Review this README and code comments
2. **🔍 Search Issues** - Look through existing GitHub issues
3. **🆕 Create an Issue** - Report bugs or request features
4. **💬 Contact the Team** - Reach out to the development team

### **🐛 Bug Reports**

When reporting bugs, please include:
- Detailed description of the issue
- Steps to reproduce
- Expected vs actual behavior
- System information (OS, Python version, browser)
- Relevant error messages or logs

### **💡 Feature Requests**

For new feature suggestions:
- Describe the feature clearly
- Explain the use case and benefits
- Consider implementation complexity
- Check if it aligns with project goals

### **📧 Contact Information**

- **Technical Issues:** Create a GitHub issue
- **Academic Inquiries:** Contact the researchers
- **General Questions:** Reach out to the website manager

## 📄 License

**© 2025 Project TEDDY Team - All Rights Reserved**

This project is proprietary software developed by the Project TEDDY research team. Unauthorized copying, modification, distribution, or use of this software is strictly prohibited.

### **Academic Use**
This software is developed for academic research purposes. For educational or research use, please contact the research team for proper licensing.

### **Commercial Use**
Commercial use, reproduction, or distribution requires explicit written permission from the Project TEDDY team.

---

<div align="center">

**🐻 Made with ❤️ by the Project TEDDY Team**

*Bringing comfort and support through innovative technology*

</div>
