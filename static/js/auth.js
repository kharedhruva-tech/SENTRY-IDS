// Auth client validation functions
document.addEventListener('DOMContentLoaded', () => {
    const registerForm = document.getElementById('register-form');
    if (registerForm) {
        registerForm.addEventListener('submit', (e) => {
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirm_password').value;
            const errorBanner = document.getElementById('error-banner');
            
            if (password.length < 6) {
                e.preventDefault();
                showError('Password must be at least 6 characters long.');
                return;
            }
            
            if (password !== confirmPassword) {
                e.preventDefault();
                showError('Passwords do not match.');
                return;
            }
        });
    }
    
    function showError(message) {
        let errorBanner = document.getElementById('error-banner');
        if (!errorBanner) {
            const form = document.querySelector('form');
            errorBanner = document.createElement('div');
            errorBanner.id = 'error-banner';
            errorBanner.className = 'alert-banner alert-banner-error';
            form.insertBefore(errorBanner, form.firstChild);
        }
        errorBanner.innerHTML = `<i class="fas fa-exclamation-triangle"></i> ${message}`;
        errorBanner.style.display = 'flex';
    }
});
