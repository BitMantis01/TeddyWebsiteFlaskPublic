# 🐻 Project TEDDY Dashboard

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.3.3-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-All%20Rights%20Reserved-red.svg)](#license)

A comprehensive web dashboard for **Project TEDDY** - an AI-powered therapeutic teddy bear that provides emotional support and comfort to people of all ages. This Flask-based web application serves as the central management platform for TEDDY devices, offering user authentication, device pairing, real-time monitoring, and configuration management.

## 📚 Table of Contents

- [🐻 Project TEDDY Dashboard](#-project-teddy-dashboard)
  - [📚 Table of Contents](#-table-of-contents)
  - [✨ Features](#-features)
  - [🛠️ Technology Stack](#️-technology-stack)
  - [📋 Prerequisites](#-prerequisites)
  - [🚀 Quick Start](#-quick-start)
  - [⚙️ Configuration](#️-configuration)
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

### 📊 **Dashboard Interface**
- **Profile Management**: Complete user profile editing capabilities
- **Device Pairing**: Simple 6-digit code pairing system for TEDDY devices
- **Real-time Monitoring**: Live battery status and connection tracking
- **Target Configuration**: Customizable settings for different user demographics
- **Activity Logs**: Historical data tracking and visualization

### 🔌 **API Endpoints**
- **Data Reception**: `/api/receive-data` - Receive telemetry from TEDDY devices
- **Configuration Broadcast**: `/api/broadcast-teddy` - Send settings to devices
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

## 🚀 Quick Start

### 1. **Clone the Repository**
```bash
git clone https://github.com/BitMantis01/TeddyWebsiteFlask.git
cd TeddyWebsiteFlask
```

### 2. **Set Up Virtual Environment** (Recommended)
```bash
# Create virtual environment
python -m venv teddy-env

# Activate virtual environment
# On Windows:
teddy-env\Scripts\activate
# On macOS/Linux:
source teddy-env/bin/activate
```

### 3. **Install Dependencies**
```bash
pip install -r requirements.txt
```

### 4. **Configure the Application**
```bash
# Copy the configuration template
cp config.json.template config.json

# Edit config.json with your actual values
# See Configuration section below for details
```

### 5. **Initialize the Database**
```bash
# The database will be created automatically on first run
python app.py
```

### 6. **Access the Application**
Open your web browser and navigate to:
```
http://localhost:5000
```

## ⚙️ Configuration

The application uses a `config.json` file for all configuration settings. Follow these steps to configure your installation:

### **Configuration Setup**

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
       "turnstile": {
           "site_key": "your-turnstile-site-key",
           "secret_key": "your-turnstile-secret-key"
       }
   }
   ```

### **Configuration Parameters**

| Parameter | Description | Required | Example |
|-----------|-------------|----------|---------|
| `secret_key` | Flask session secret key | ✅ | `"randomly-generated-secret-key"` |
| `database_path` | SQLite database file path | ✅ | `"teddy.db"` |
| `api_key` | API authentication key | ✅ | `"your-api-key-here"` |
| `website_url` | Your website domain | ✅ | `"your-domain.com"` |
| `manager_name` | Manager/Contact name | ✅ | `"Your Name"` |
| `manager_url` | Manager contact URL | ✅ | `"your-site.com"` |
| `turnstile.site_key` | Cloudflare Turnstile site key | ✅ | `"0x4AAAAAAAA..."` |
| `turnstile.secret_key` | Cloudflare Turnstile secret key | ✅ | `"0x4AAAAAAAA..."` |

### **Security Keys Generation**

```bash
# Generate a secure secret key
python -c "import secrets; print(secrets.token_hex(32))"

# Generate a secure API key
python -c "import secrets; print(secrets.token_hex(32))"
```

### **Cloudflare Turnstile Setup**

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
| `created_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Account creation date |

### **TEDDY Devices Table** (`teddy_devices`)
Manages TEDDY device registrations and pairings.

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
Authorization: Bearer your-api-key-here
```

### **📤 Receive Data Endpoint**

**Endpoint:** `POST /api/receive-data`

**Description:** Receives telemetry data from TEDDY devices including battery levels and status updates.

**Request Headers:**
```http
Content-Type: application/json
X-API-Key: your-api-key-here
```

**Request Body:**
```json
{
    "teddycode": "123456",
    "battery": 85
}
```

**Request Parameters:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `teddycode` | string | ✅ | 6-digit device identifier |
| `battery` | integer | ✅ | Battery level (0-100) |

**Response (Success):**
```json
{
    "success": true,
    "message": "Data received successfully"
}
```

**Response (Error):**
```json
{
    "success": false,
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
| 👩‍🔬 **Lead Researcher** | Shanealei Salve L. Sta. Maria |
| 👩‍💻 **Technical Lead** | Khasheica Kleane P. Lacap |
| 🧠 **AI Specialist** | Felix Andrei M. Camillon |
| 📊 **Data Analyst** | Matthew Gabriel M. Generoso |
| 🔧 **Hardware Engineer** | Mark James D. Lazaro |
| 🎨 **UI/UX Designer** | Alson John D. Milante |

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
- **Academic Inquiries:** Contact the research adviser
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
