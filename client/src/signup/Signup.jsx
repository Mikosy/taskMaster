import React, { useState } from 'react';
import "../signup/signup.css";
import { Link } from "react-router-dom";
import 'bootstrap/dist/css/bootstrap.min.css'

const Signup = () => {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [role, setRole] = useState("");
  const [title, setTitle] = useState("");
  const [admin, setAdmin] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);

  // Handle checkbox change for admin
  const handleAdminChange = () => {
    setAdmin(!admin);  // Toggle the admin field
  };

  const handleSignup = async (e) => {
    e.preventDefault();

    // Basic client-side validation
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    try {
      const response = await fetch("http://localhost:5000/register", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ name, email, password, role, title, admin }),
      });

      const data = await response.json();

      if (response.ok) {
        setSuccess("Signup successful! Please log in.");
        setError(null);
        setName("");
        setEmail("");
        setPassword("");
        setConfirmPassword("");
        setRole("");
        setTitle("");
        setAdmin(false);
      } else {
        setError(data.message || "Signup failed.");
        setSuccess(null);
      }
    } catch (err) {
      setError("Something went wrong. Please try again.");
      setSuccess(null);
    }
  };
  return (
    <>
      <div className="row container-fluid">
        <div className="col-xl-6 col-md-6 col-sm-12 bg-light d-flex flex-column align-items-center justify-content-center svg-part">
          <svg xmlns="http://www.w3.org/2000/svg" width="300" height="300" fill="currentColor" class="bi bi-ui-checks-grid" viewBox="0 0 16 16">
            <path d="M2 10h3a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1H2a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1zm9-9h3a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1h-3a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1zm0 9a1 1 0 0 0-1 1v3a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-3a1 1 0 0 0-1-1h-3zm0-10a2 2 0 0 0-2 2v3a2 2 0 0 0 2 2h3a2 2 0 0 0 2-2V2a2 2 0 0 0-2-2h-3zM2 9a2 2 0 0 0-2 2v3a2 2 0 0 0 2 2h3a2 2 0 0 0 2-2v-3a2 2 0 0 0-2-2H2zm7 2a2 2 0 0 1 2-2h3a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2h-3a2 2 0 0 1-2-2v-3zM0 2a2 2 0 0 1 2-2h3a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V2zm5.354.854a.5.5 0 1 0-.708-.708L3 3.793l-.646-.647a.5.5 0 1 0-.708.708l1 1a.5.5 0 0 0 .708 0l2-2z" />
          </svg>
          <h1 className="mt-2 svg-text">TaskMaster</h1>
          <p>Manage all your tasks in one place!</p>
        </div>
        <div className="col-xl-6 col-md-6 col-sm-12 ">
          <div className="addUser">
            <h3>SIGNUP</h3>
            <form className="addUserForm" onSubmit={handleSignup}>
              <div className="inputGroup">
                {error && <div className="alert alert-danger">{error}</div>}
                {success && <div className="alert alert-success">{success}</div>}

                <label htmlFor="name">Name:</label>
                <input
                  type="text"
                  id="name"
                  name="name"
                  required
                  className="form-control"
                  autoComplete="off"
                  placeholder="Enter your name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
                <label htmlFor="email">Email:</label>
                <input
                  type="email"
                  id="email"
                  name="email"
                  required
                  className="form-control"
                  autoComplete="off"
                  placeholder="Enter your Email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
                <label htmlFor="Password">Password:</label>
                <input
                  type="password"
                  id="password"
                  name="password"
                  required
                  className="form-control"
                  autoComplete="off"
                  placeholder="Enter Password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
                <label htmlFor="confirmPassword">Confirm Password:</label>
                <input
                  type="password"
                  id="confirmPassword"
                  name="confirmPassword"
                  required
                  className="form-control"
                  placeholder="Confirm your password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                />
                <label htmlFor="Password">Role:</label>
                <input
                  type="text"
                  id="role"
                  name="role"
                  required
                  className="form-control"
                  autoComplete="off"
                  placeholder="Developer"
                  value={role}
                  onChange={(e) => setRole(e.target.value)}
                />
                <label htmlFor="Password">Title:</label>
                <input
                  type="text"
                  id="title"
                  name="title"
                  required
                  className="form-control"
                  autoComplete="off"
                  placeholder="Frontend"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                />
                <label htmlFor="admin" className="d-flex gap-2" >
                  <input
                    type="checkbox"
                    id="admin"
                    required
                    checked={admin}
                    onChange={handleAdminChange}
                    className="form-checkbox"
                  />
                  Admin
                </label>

                <button type="submit" class="btn btn-lg btn-success mt-4 fw-bold">
                  Sign Up
                </button>
              </div>
            </form>
            <div className="login">
              <p>Already have an Account? <Link to="/login" type="submit" className="text-dark">
                Login
              </Link></p>

            </div>
          </div>
        </div>
      </div>

    </>
  );
};

export default Signup;
