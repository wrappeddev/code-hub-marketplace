// Authentication utilities for Discord OAuth

class AuthManager {
    constructor() {
        this.sessionToken = localStorage.getItem('sessionToken');
        this.user = null;
    }

    // Check if user is authenticated
    isAuthenticated() {
        return !!this.sessionToken;
    }

    // Get current user
    getCurrentUser() {
        return this.user;
    }

    // Set session token
    setSession(token, user) {
        this.sessionToken = token;
        this.user = user;
        localStorage.setItem('sessionToken', token);
    }

    // Clear session
    clearSession() {
        this.sessionToken = null;
        this.user = null;
        localStorage.removeItem('sessionToken');
        localStorage.removeItem('oauthState');
    }

    // Verify session with server
    async verifySession() {
        if (!this.sessionToken) {
            return false;
        }

        try {
            const response = await fetch('/api/get-user', {
                headers: {
                    'Authorization': `Bearer ${this.sessionToken}`
                }
            });

            if (response.ok) {
                const data = await response.json();
                this.user = data.user;
                return true;
            } else {
                this.clearSession();
                return false;
            }
        } catch (error) {
            console.error('Session verification error:', error);
            this.clearSession();
            return false;
        }
    }

    // Get Discord avatar URL
    getAvatarUrl(user = null) {
        const userData = user || this.user;
        if (!userData) return null;

        if (userData.avatar) {
            return `https://cdn.discordapp.com/avatars/${userData.id}/${userData.avatar}.png`;
        } else {
            return `https://cdn.discordapp.com/embed/avatars/${userData.discriminator % 5}.png`;
        }
    }

    // Format Discord username
    getDisplayName(user = null) {
        const userData = user || this.user;
        if (!userData) return null;

        return `${userData.username}#${userData.discriminator}`;
    }

    // Make authenticated API request
    async apiRequest(endpoint, options = {}) {
        if (!this.sessionToken) {
            throw new Error('Not authenticated');
        }

        const defaultOptions = {
            headers: {
                'Authorization': `Bearer ${this.sessionToken}`,
                ...options.headers
            }
        };

        const response = await fetch(endpoint, { ...options, ...defaultOptions });
        
        if (response.status === 401) {
            this.clearSession();
            throw new Error('Session expired');
        }

        return response;
    }
}

// Create global auth manager instance
window.authManager = new AuthManager();

// Utility functions for common auth operations
window.authUtils = {
    // Redirect to login if not authenticated
    requireAuth() {
        if (!window.authManager.isAuthenticated()) {
            window.location.href = '/submit.html';
            return false;
        }
        return true;
    },

    // Show/hide elements based on auth status
    updateAuthUI() {
        const authElements = document.querySelectorAll('[data-auth-required]');
        const noAuthElements = document.querySelectorAll('[data-no-auth-required]');
        const isAuth = window.authManager.isAuthenticated();

        authElements.forEach(el => {
            el.style.display = isAuth ? '' : 'none';
        });

        noAuthElements.forEach(el => {
            el.style.display = isAuth ? 'none' : '';
        });
    },

    // Format file size for display
    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },

    // Validate image file
    validateImageFile(file) {
        const validTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
        const maxSize = 5 * 1024 * 1024; // 5MB

        if (!validTypes.includes(file.type)) {
            return {
                valid: false,
                error: `Invalid file type. Only JPEG, PNG, GIF, and WebP are allowed.`
            };
        }

        if (file.size > maxSize) {
            return {
                valid: false,
                error: `File too large. Maximum size is ${this.formatFileSize(maxSize)}.`
            };
        }

        return { valid: true };
    },

    // Show notification
    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `fixed top-4 right-4 z-50 p-4 rounded-lg shadow-lg max-w-sm transition-all duration-300 transform translate-x-full`;
        
        // Set colors based on type
        const colors = {
            success: 'bg-green-600 text-white',
            error: 'bg-red-600 text-white',
            warning: 'bg-yellow-600 text-white',
            info: 'bg-blue-600 text-white'
        };
        
        notification.className += ` ${colors[type] || colors.info}`;
        notification.textContent = message;

        document.body.appendChild(notification);

        // Animate in
        setTimeout(() => {
            notification.classList.remove('translate-x-full');
        }, 100);

        // Auto remove after 5 seconds
        setTimeout(() => {
            notification.classList.add('translate-x-full');
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, 5000);
    }
};
