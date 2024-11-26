document.addEventListener("DOMContentLoaded", () => {
    const welcomeUserElement = document.getElementById("welcomeUser");
    const authButtons = document.getElementById("authButtons");

    // Function to display the welcome message
    function displayWelcomeMessage() {
        const token = localStorage.getItem("jwtToken");

        if (token) {
            // Decode the token to extract user information
            const userPayload = parseJwt(token);

            if (userPayload && userPayload.name) {
                // Update welcome message
                welcomeUserElement.textContent = `Welcome, ${userPayload.name}!`;

                // Replace Sign up button with Logout button
                authButtons.innerHTML = `
                    <button id="logoutButton"
                            class="ms-auto btn btn-md rounded-2 py-1 ps-3 pe-3 text-light logout fw-bold">
                        Logout
                    </button>
                `;

                // Attach logout functionality
                document.getElementById("logoutButton").addEventListener("click", () => {
                    logoutUser();
                });
            } else {
                // Invalid token, clear storage and reset UI
                console.warn("Invalid token payload:", userPayload);
                clearUserSession();
            }
        } else {
            // No token, show default message
            resetToSignUp();
        }
    }

    // Function to decode JWT token
    function parseJwt(token) {
        try {
            const base64Url = token.split(".")[1];
            const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
            const jsonPayload = decodeURIComponent(
                atob(base64)
                    .split("")
                    .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
                    .join("")
            );
            return JSON.parse(jsonPayload);
        } catch (e) {
            console.error("Failed to parse JWT:", e);
            return null;
        }
    }

    // Function to clear user session
    function clearUserSession() {
        localStorage.removeItem("jwtToken");
        resetToSignUp();
    }

    // Function to reset to Sign up state
    function resetToSignUp() {
        welcomeUserElement.textContent = "Welcome!";
        authButtons.innerHTML = `
            <a href="../frontView/login.html"
               class="ms-auto btn btn-md rounded-2 py-1 ps-3 pe-3 text-light signup fw-bold">
               Login
            </a>
        `;
    }

    // Function to handle logout
    function logoutUser() {
        clearUserSession();
        // alert("You have been logged out.");
        // window.location.reload(); // Reload to reset UI
        window.location.href = 'http://127.0.0.1:5500/frontView/login.html';
    }

    // Call the function to display the welcome message on page load
    displayWelcomeMessage();
});


// document.getElementById("createTaskForm").addEventListener("submit", async function (event) {
//     event.preventDefault();

//     // Collect form data
//     const title = document.getElementById("taskTitle").value;
//     const description = document.getElementById("taskDescription").value;
//     const status = document.getElementById("taskStatus").value;
//     const dueDate = document.getElementById("dueDate").value;
//     const assignedUsersInput = document.getElementById("assignedUsers").value;
//     const files = document.getElementById("taskFiles").files;

//     // Convert assigned users input to an array of emails
//     const assignedUsers = assignedUsersInput.split(',').map(email => email.trim());

//     // Prepare form data (including files)
//     const formData = new FormData();
//     formData.append("title", title);
//     formData.append("description", description);
//     formData.append("status", status);
//     formData.append("dueDate", dueDate);
//     formData.append("assignedUsers", JSON.stringify(assignedUsers)); // Stringify the array
//     // Attach files
//     Array.from(files).forEach(file => formData.append("files", file));

//     console.log('form date =============>', formData);




//     // Retrieve token from localStorage
//     const token = localStorage.getItem("jwtToken");
//     console.log("Token from localStorage==========> ", token);

//     // Define API endpoint
//     const apiEndpoint = "http://localhost:5000/create";

//     try {
//         // Send POST request with form data
//         const response = await fetch(apiEndpoint, {
//             method: "POST",
//             headers: {
//                 "Authorization": `Bearer ${token}`,
//             },
//             body: formData,

//         });


//         const data = await response.json();
//         const responseMessage = document.getElementById("responseMessage");

//         // Handle response
//         if (response.ok) {
//             responseMessage.innerHTML = `<div class="alert alert-success">${data.message}</div>`;
//         } else {
//             responseMessage.innerHTML = `<div class="alert alert-danger">${data.message || "An error occurred"}</div>`;
//         }
//     } catch (error) {
//         console.error("Error:", error);
//         document.getElementById("responseMessage").innerHTML = `<div class="alert alert-danger">Failed to create task</div>`;
//     }
// });


document.getElementById("createTaskForm").addEventListener("submit", async function (event) {
    event.preventDefault(); // Prevent normal form submission

    // Collect form data
    const title = document.getElementById("taskTitle").value;
    const description = document.getElementById("taskDescription").value;
    const status = document.getElementById("taskStatus").value;
    const dueDate = document.getElementById("dueDate").value;
    const assignedUsersInput = document.getElementById("assignedUsers").value;
    const files = document.getElementById("taskFiles").files;

    // Prepare form data (including files)
    const formData = new FormData();

    try {
        // Append non-file fields
        if (!title) throw new Error("Title is required");
        formData.append("title", title);

        if (!description) throw new Error("Description is required");
        formData.append("description", description);

        if (!status) throw new Error("Status is required");
        formData.append("status", status);

        if (!dueDate) throw new Error("Due date is required");
        formData.append("dueDate", dueDate);

        if (!assignedUsersInput) throw new Error("Assigned users are required");
        const assignedUsers = assignedUsersInput.split(',').map(email => email.trim());
        if (!assignedUsers.every(email => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) {
            throw new Error("One or more assigned users' emails are invalid.");
        }
        formData.append("assignedUsers", JSON.stringify(assignedUsers)); // Stringify the array

        // Attach files (if present)
        if (files.length > 0) {
            Array.from(files).forEach(file => formData.append("files", file));
        } else {
            throw new Error("At least one file is required.");
        }

        // Send the form data
        const token = localStorage.getItem("jwtToken"); // Retrieve token from localStorage
        if (!token) throw new Error("No token found. User is not authenticated.");

        const response = await fetch("http://localhost:5000/create", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${token}`,
            },
            body: formData, // Send FormData object
        });

        const data = await response.json();
        const responseMessage = document.getElementById("responseMessage");

        if (response.ok) {
            responseMessage.innerHTML = `<div class="alert alert-success">${data.message}</div>`;
        } else {
            responseMessage.innerHTML = `<div class="alert alert-danger">${data.message || "An error occurred"}</div>`;
        }

    } catch (error) {
        // Log the specific error that occurred
        console.error("Error:", error);
        document.getElementById("responseMessage").innerHTML = `<div class="alert alert-danger">${error.message}</div>`;
    }
});
