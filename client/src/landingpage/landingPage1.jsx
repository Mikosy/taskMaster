import React, { useEffect, useState } from 'react';
import "../landingpage/landingpage.css";
import { Link, useNavigate } from "react-router-dom";
import 'bootstrap/dist/css/bootstrap.min.css';
import CustomNavbar from '../components/CustomNavbar.jsx';
import AddTaskModal from '../components/AddTaskModal.jsx'
import { Card } from 'react-bootstrap';


const LandingPage = () => {
    const [showTaskModal, setShowTaskModal] = useState(false);
    const [user, setUser] = useState(null);
    const navigate = useNavigate();

    useEffect(() => {
        // Retrieve user data from localStorage
        const storedUser = localStorage.getItem('user');
        if (storedUser) {
            setUser(JSON.parse(storedUser));
        }
    }, []);

    const handleLogout = () => {
        // Clear localStorage
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        // Redirect to login page
        navigate('/login');
    };

    const navLinks = [
        // { label: 'Home', href: '#home' },
        // { label: 'About', href: '#about' },
        // { label: 'Services', href: '#services' },
        // { label: 'Contact', href: '#contact' },
    ];
    const handleShowTaskModal = () => setShowTaskModal(true);
    const handleCloseTaskModal = () => setShowTaskModal(false);

    // const userId = req.userId;

    return (
        <>
            <CustomNavbar brand="TaskMaster" links={navLinks} user={user} handleLogout={handleLogout} />

            {/* {error && <div className="alert alert-danger">{error}</div>} */}
            <div className='card'>
                <div className='card-body'>
                    <h1>Welcome, {user ? user.name || user.email : 'Guest'}!</h1>
                    <small className='text-light'>Your one-stop solution for amazing experiences. create and assign task at ease.</small>
                </div>

            </div>

            <div className='addTask container mt-3 mb-0'>
                <button className='btn btn-lg fw-bold text-light teal-btn' onClick={handleShowTaskModal}>Add Task</button>
            </div>

            <div className="landing-content mt-5 pt-4 container">
                <section id="task page" className="section-task">
                    <div className='row'>
                        <div className='col-xl-4 col-md-4 col-sm-12'>
                            <Card className='card-tasks shadow-sm'>

                            </Card>
                        </div>
                    </div>
                </section>

            </div>







            {/* Task Modals */}
            <AddTaskModal show={showTaskModal} handleClose={handleCloseTaskModal} />
        </>
    );
};

export default LandingPage;


