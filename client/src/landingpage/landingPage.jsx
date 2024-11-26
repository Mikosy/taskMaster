import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from "react-router-dom";
import 'bootstrap/dist/css/bootstrap.min.css';
import CustomNavbar from '../components/CustomNavbar.jsx';
import AddTaskModal from '../components/AddTaskModal.jsx';
import { Card } from 'react-bootstrap';

const LandingPage = () => {
    const [showTaskModal, setShowTaskModal] = useState(false);
    const [user, setUser] = useState(null);
    const [tasks, setTasks] = useState([]); // To store tasks
    const navigate = useNavigate();

    useEffect(() => {
        // Retrieve user data from localStorage
        const storedUser = localStorage.getItem('user');
        if (storedUser) {
            setUser(JSON.parse(storedUser));
        }
    }, []);

    useEffect(() => {
        // Fetch tasks for the logged-in user if user is available
        if (user) {
            const fetchTasks = async () => {
                try {
                    const response = await fetch(`/tasks/${user.userId}`, {
                        headers: {
                            'Authorization': `Bearer ${localStorage.getItem('token')}` // If you use JWT token
                        }
                    });
                    const data = await response.json();
                    if (data.success) {
                        setTasks(data.tasks); // Set tasks to state
                    } else {
                        console.error(data.error);
                    }
                } catch (error) {
                    console.error('Error fetching tasks:', error);
                }
            };
            fetchTasks();
        }
    }, [user]); // Run this useEffect when the user is updated

    const handleLogout = () => {
        // Clear localStorage
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        // Redirect to login page
        navigate('/login');
    };

    const handleShowTaskModal = () => setShowTaskModal(true);
    const handleCloseTaskModal = () => setShowTaskModal(false);

    return (
        <>
            <CustomNavbar brand="TaskMaster" user={user} handleLogout={handleLogout} />

            <div className='card'>
                <div className='card-body'>
                    <h1>Welcome, {user ? user.name || user.email : 'Guest'}!</h1>
                    <small className='text-light'>Your one-stop solution for amazing experiences. Create and assign tasks with ease.</small>
                </div>
            </div>

            <div className='addTask container mt-3 mb-0'>
                <button className='btn btn-lg fw-bold text-light teal-btn' onClick={handleShowTaskModal}>Add Task</button>
            </div>

            <div className="landing-content mt-5 pt-4 container">
                <section id="task page" className="section-task">
                    <div className="row">
                        {tasks.length > 0 ? tasks.map(task => (
                            <div key={task._id} className="col-xl-4 col-md-4 col-sm-12">
                                <Card className="card-tasks shadow-sm">
                                    <Card.Body>
                                        <Card.Title>{task.title}</Card.Title>
                                        <Card.Text>{task.description}</Card.Text>
                                        <ul>
                                            {task.assignedUsers?.map(user => (
                                                <li key={user._id}>{user.name} - {user.role}</li>
                                            )) || <li>No users assigned</li>}
                                        </ul>
                                    </Card.Body>
                                </Card>
                            </div>
                        )) : (
                            <div>No tasks found</div>
                        )}
                    </div>
                </section>
            </div>

            {/* Task Modals */}
            <AddTaskModal show={showTaskModal} handleClose={handleCloseTaskModal} />
        </>
    );
};

export default LandingPage;
