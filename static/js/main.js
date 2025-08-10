// Project TEDDY JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Initialize all components
    initializeNavigation();
    initializeAnimations();
    initializeFormValidation();
    initializeDashboard();
});

// Navigation functionality
function initializeNavigation() {
    const navbar = document.querySelector('.navbar');
    
    if (navbar && navbar.classList.contains('fixed-top')) {
        // Add scroll effect to navbar
        window.addEventListener('scroll', function() {
            if (window.scrollY > 50) {
                navbar.style.background = 'rgba(255, 255, 255, 0.98)';
                navbar.style.boxShadow = '0 4px 20px rgba(0, 0, 0, 0.1)';
            } else {
                navbar.style.background = 'rgba(255, 255, 255, 0.95)';
                navbar.style.boxShadow = 'none';
            }
        });
    }
    
    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
}

// Animation functionality
function initializeAnimations() {
    // Intersection Observer for fade-in animations
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };
    
    const observer = new IntersectionObserver(function(entries) {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, observerOptions);
    
    // Observe elements with animation classes
    document.querySelectorAll('.feature-card, .team-card, .research-stat').forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(30px)';
        el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
        observer.observe(el);
    });
    
    // Counter animation for battery percentage
    const batteryPercentage = document.querySelector('.battery-percentage');
    if (batteryPercentage) {
        const targetValue = parseInt(batteryPercentage.textContent);
        animateCounter(batteryPercentage, 0, targetValue, 1000);
    }
}

// Counter animation function
function animateCounter(element, start, end, duration) {
    const range = end - start;
    const increment = range / (duration / 16);
    let current = start;
    
    const timer = setInterval(() => {
        current += increment;
        if (current >= end) {
            current = end;
            clearInterval(timer);
        }
        element.textContent = Math.floor(current) + '%';
    }, 16);
}

// Form validation
function initializeFormValidation() {
    // Real-time password strength indicator
    const passwordInput = document.getElementById('password');
    if (passwordInput) {
        passwordInput.addEventListener('input', function() {
            updatePasswordStrength(this.value);
        });
    }
    
    // Email validation
    const emailInputs = document.querySelectorAll('input[type="email"]');
    emailInputs.forEach(input => {
        input.addEventListener('blur', function() {
            validateEmail(this);
        });
    });
    
    // TEDDY code input formatting
    const teddyCodeInput = document.getElementById('teddyCode');
    if (teddyCodeInput) {
        teddyCodeInput.addEventListener('input', function() {
            // Only allow numbers
            this.value = this.value.replace(/[^0-9]/g, '');
            
            // Limit to 6 digits
            if (this.value.length > 6) {
                this.value = this.value.slice(0, 6);
            }
            
            // Visual feedback
            if (this.value.length === 6) {
                this.classList.add('is-valid');
                this.classList.remove('is-invalid');
            } else {
                this.classList.remove('is-valid');
                this.classList.add('is-invalid');
            }
        });
    }
    
    // Form submission validation
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            if (!validateForm(this)) {
                e.preventDefault();
            }
        });
    });
}

// Comprehensive form validation
function validateForm(form) {
    let isValid = true;
    const errors = [];
    
    // Validate email fields
    const emailInputs = form.querySelectorAll('input[type="email"]');
    emailInputs.forEach(input => {
        if (!validateEmailInput(input.value)) {
            input.classList.add('is-invalid');
            errors.push('Please enter a valid email address');
            isValid = false;
        } else {
            input.classList.remove('is-invalid');
        }
    });
    
    // Validate password fields
    const passwordInputs = form.querySelectorAll('input[type="password"][required]');
    passwordInputs.forEach(input => {
        if (input.id === 'password') {
            const validation = validatePasswordStrength(input.value);
            if (!validation.isValid) {
                input.classList.add('is-invalid');
                errors.push(...validation.errors);
                isValid = false;
            } else {
                input.classList.remove('is-invalid');
                input.classList.add('is-valid');
            }
        } else if (input.value.length < 1) {
            input.classList.add('is-invalid');
            errors.push('Password is required');
            isValid = false;
        } else {
            input.classList.remove('is-invalid');
        }
    });
    
    // Validate TEDDY code
    const teddyCodeInput = form.querySelector('#teddyCode');
    if (teddyCodeInput && teddyCodeInput.value && !/^\d{6}$/.test(teddyCodeInput.value)) {
        teddyCodeInput.classList.add('is-invalid');
        errors.push('TEDDY code must be exactly 6 digits');
        isValid = false;
    }
    
    // Validate Turnstile CAPTCHA
    const turnstileResponse = form.querySelector('input[name="cf-turnstile-response"]');
    if (turnstileResponse && !turnstileResponse.value) {
        errors.push('Please complete the security verification');
        isValid = false;
    }
    
    // Validate password confirmation
    const confirmPasswordInput = form.querySelector('#confirmPassword');
    const passwordInput = form.querySelector('#password');
    if (confirmPasswordInput && passwordInput) {
        if (confirmPasswordInput.value !== passwordInput.value) {
            confirmPasswordInput.classList.add('is-invalid');
            errors.push('Passwords do not match');
            isValid = false;
        } else if (confirmPasswordInput.value.length > 0) {
            confirmPasswordInput.classList.remove('is-invalid');
            confirmPasswordInput.classList.add('is-valid');
        }
    }
    
    // Show errors if any
    if (errors.length > 0) {
        showNotification(errors.join('<br>'), 'danger');
    }
    
    return isValid;
}

function validateEmailInput(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function validatePasswordStrength(password) {
    const errors = [];
    
    if (password.length < 8) errors.push('Password must be at least 8 characters long');
    if (!/[A-Z]/.test(password)) errors.push('Password must contain at least one uppercase letter (A-Z)');
    if (!/[a-z]/.test(password)) errors.push('Password must contain at least one lowercase letter (a-z)');
    if (!/[0-9]/.test(password)) errors.push('Password must contain at least one number (0-9)');
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) errors.push('Password must contain at least one special character (!@#$%^&*)');
    
    return {
        isValid: errors.length === 0,
        errors: errors
    };
}

// Password strength indicator
function updatePasswordStrength(password) {
    const strengthIndicator = document.getElementById('passwordStrength');
    if (!strengthIndicator) return;
    
    // Show the strength indicator
    strengthIndicator.style.display = 'block';
    
    let strength = 0;
    let feedback = [];
    const requirements = [
        { regex: /.{8,}/, text: 'At least 8 characters', element: null },
        { regex: /[A-Z]/, text: 'One uppercase letter (A-Z)', element: null },
        { regex: /[a-z]/, text: 'One lowercase letter (a-z)', element: null },
        { regex: /[0-9]/, text: 'One number (0-9)', element: null },
        { regex: /[!@#$%^&*(),.?":{}|<>]/, text: 'One special character (!@#$%^&*)', element: null }
    ];
    
    // Update requirements list visual feedback
    const requirementsList = document.querySelector('.password-requirements ul');
    if (requirementsList) {
        const listItems = requirementsList.querySelectorAll('li');
        requirements.forEach((req, index) => {
            if (listItems[index]) {
                if (req.regex.test(password)) {
                    listItems[index].classList.add('valid');
                    strength++;
                } else {
                    listItems[index].classList.remove('valid');
                    feedback.push(req.text);
                }
            }
        });
    }
    
    const strengthLevels = ['very-weak', 'weak', 'fair', 'good', 'strong'];
    const strengthTexts = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];
    const strengthColors = ['#ef4444', '#f59e0b', '#eab308', '#10b981', '#059669'];
    
    // Remove all strength classes
    strengthLevels.forEach(level => {
        strengthIndicator.classList.remove(`strength-${level}`);
    });
    
    // Add current strength class
    const currentStrength = Math.min(strength, strengthLevels.length - 1);
    strengthIndicator.classList.add(`strength-${strengthLevels[currentStrength]}`);
    
    // Update text
    const strengthText = strengthIndicator.querySelector('.password-strength-text');
    if (strengthText) {
        strengthText.textContent = `Password Strength: ${strengthTexts[currentStrength]}`;
        strengthText.style.color = strengthColors[currentStrength];
    }
    
    return strength >= 5; // All requirements met
}

// Email validation
function validateEmail(emailInput) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const isValid = emailRegex.test(emailInput.value);
    
    if (isValid) {
        emailInput.classList.add('is-valid');
        emailInput.classList.remove('is-invalid');
    } else if (emailInput.value.length > 0) {
        emailInput.classList.add('is-invalid');
        emailInput.classList.remove('is-valid');
    }
}

// Dashboard functionality
function initializeDashboard() {
    // Auto-refresh functionality
    const refreshInterval = 30000; // 30 seconds
    
    if (document.querySelector('.battery-display')) {
        setInterval(refreshBatteryStatus, refreshInterval);
    }
    
    // Connection status animation
    const statusIndicator = document.querySelector('.status-indicator.connected');
    if (statusIndicator) {
        setInterval(() => {
            statusIndicator.style.animation = 'pulse 1s ease-in-out';
            setTimeout(() => {
                statusIndicator.style.animation = '';
            }, 1000);
        }, 5000);
    }
    
    // Initialize tooltips
    initializeTooltips();
}

// Refresh battery status
function refreshBatteryStatus() {
    const batteryDisplay = document.querySelector('.battery-display');
    if (!batteryDisplay) return;
    
    // Add loading state
    batteryDisplay.style.opacity = '0.7';
    
    // Simulate API call (replace with actual endpoint)
    setTimeout(() => {
        batteryDisplay.style.opacity = '1';
        
        // Update last updated time
        const lastUpdated = document.querySelector('.battery-display small');
        if (lastUpdated) {
            lastUpdated.textContent = 'Last updated: ' + new Date().toLocaleTimeString();
        }
    }, 500);
}

// Initialize tooltips
function initializeTooltips() {
    // Bootstrap tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

// Utility functions
function showNotification(message, type = 'success') {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} alert-dismissible fade show notification`;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 9999;
        max-width: 400px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    `;
    notification.innerHTML = `
        <div>${message}</div>
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(notification);
    
    // Auto-remove after 8 seconds for error messages, 5 for others
    const timeout = type === 'danger' || type === 'error' ? 8000 : 5000;
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, timeout);
}

function formatDate(date) {
    return new Date(date).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
    });
}

function formatTime(date) {
    return new Date(date).toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit'
    });
}

// Error handling
window.addEventListener('error', function(e) {
    console.error('JavaScript Error:', e.error);
    
    // Show user-friendly error message for critical errors
    if (e.error && e.error.message.includes('network')) {
        showNotification('Network connection issue. Please check your internet connection.', 'warning');
    }
});

// Performance monitoring
if ('performance' in window) {
    window.addEventListener('load', function() {
        setTimeout(() => {
            const perfData = performance.getEntriesByType('navigation')[0];
            console.log('Page load time:', perfData.loadEventEnd - perfData.fetchStart + 'ms');
        }, 0);
    });
}

// Export functions for global use
window.TeddyApp = {
    showNotification,
    formatDate,
    formatTime,
    refreshBatteryStatus,
    resetTurnstile
};

// Turnstile helper function
function resetTurnstile() {
    if (typeof turnstile !== 'undefined') {
        const turnstileWidget = document.querySelector('.cf-turnstile');
        if (turnstileWidget) {
            turnstile.reset();
        }
    }
}
