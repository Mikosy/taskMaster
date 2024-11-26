document.getElementById('loginForm').addEventListener('submit', async (event) => {
    event.preventDefault();

    // Gather form data
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    try {
        // Make POST request to login the user
        const response = await fetch('http://localhost:5000/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, password }),
        });

        // Parse the JSON response
        const result = await response.json();

        if (response.ok) {
            // Store the token in localStorage
            localStorage.setItem('jwtToken', result.token);
            console.log("Token saved:", result.token);

            // Show success message
            showAlert('Login successful! Redirecting to dashboard...', 'success');

            // Redirect to dashboard page after a delay
            setTimeout(() => {
                window.location.href = 'http://127.0.0.1:5500/frontView/index.html';
            }, 2000);
        } else {
            // Handle login errors
            showAlert(result.message || 'Login failed', 'danger');
        }
    } catch (error) {
        console.error('Error:', error);
        showAlert('An error occurred during login.', 'danger');
    }
});

// Function to show Bootstrap alerts
function showAlert(message, type) {
    const alertPlaceholder = document.getElementById('alertPlaceholder');
    alertPlaceholder.innerHTML = `
        <div class="alert alert-${type} alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    `;
}
