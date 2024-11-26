import React, { useState } from 'react';
import { Modal, Button, Form, Alert } from 'react-bootstrap';

const AddTaskModal = ({ show, handleClose }) => {
    const [title, setTitle] = useState('');
    const [description, setDescription] = useState('');
    const [assignedUsers, setAssignedUsers] = useState('');
    const [status, setStatus] = useState('todo');
    const [dueDate, setDueDate] = useState('');
    const [file, setFile] = useState(null);
    const [message, setMessage] = useState(null);

    // Handle file change
    const handleFileChange = (e) => {
        const selectedFile = e.target.files[0]; // Get the first file
        if (selectedFile) {
            setFile(selectedFile); // Set the file to the state
        }
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        const emailArray = assignedUsers
            .split(',')
            .map(email => email.trim()) // Remove extra spaces
            .filter(email => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)); // Validate email format

        if (emailArray.length === 0) {
            setMessage({ type: 'danger', text: 'Please enter at least one valid email address.' });
            return;
        }


        const formData = new FormData();
        formData.append('title', title);
        formData.append('description', description);
        formData.append('assignedUsers', JSON.stringify(emailArray)); // Convert to JSON array of emails
        formData.append('status', status);
        formData.append('dueDate', dueDate);
        if (file) {
            formData.append('files', file);
        }

        const token = localStorage.getItem('token'); // Get the token from localStorage

        try {
            const response = await fetch('http://localhost:5000/create', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`, // Add token to the request header
                },
                body: formData,
            });

            const result = await response.json();

            if (response.ok) {
                setMessage({ type: 'success', text: 'Task added successfully!' });
                // Reset form fields
                setTitle('');
                setDescription('');
                setAssignedUsers('');
                setStatus('todo');
                setDueDate('');
                setFile(null);
                handleClose();
            } else {
                const errorData = await response.json();
                console.log('Error response:', errorData);  // Log the error details
                setMessage({ type: 'danger', text: result.message || 'Error creating task.' });
                // setMessage({ type: 'danger', text: errorData.message || 'Failed to add task' });
            }
        } catch (error) {
            console.error('Error occurred:', error);  // Log the error details
            setMessage({ type: 'danger', text: 'An error occurred while adding the task' });
        }
    };



    return (
        <Modal show={show} onHide={handleClose}>
            <Modal.Header closeButton>
                <Modal.Title>Add New Task</Modal.Title>
            </Modal.Header>
            <Modal.Body>
                {message && <Alert variant={message.type}>{message.text}</Alert>}
                <Form onSubmit={handleSubmit}>
                    <Form.Group className="mb-3" controlId="formTaskTitle">
                        <Form.Label>Title</Form.Label>
                        <Form.Control
                            type="text"
                            placeholder="Enter task title"
                            value={title}
                            onChange={(e) => setTitle(e.target.value)}
                            required
                        />
                    </Form.Group>
                    <Form.Group className="mb-3" controlId="formTaskDescription">
                        <Form.Label>Description</Form.Label>
                        <Form.Control
                            as="textarea"
                            rows={3}
                            placeholder="Enter task description"
                            value={description}
                            onChange={(e) => setDescription(e.target.value)}
                            required
                        />
                    </Form.Group>
                    <Form.Group className="mb-3" controlId="formAssignedUsers">
                        <Form.Label>Assigned Users (comma-separated IDs)</Form.Label>
                        <Form.Control
                            type="text"
                            placeholder='e.g., "jane@gmail.com, john@gmail.com"'
                            value={assignedUsers}
                            onChange={(e) => setAssignedUsers(e.target.value)}
                            required
                        />
                    </Form.Group>
                    <Form.Group className="mb-3" controlId="formTaskStatus">
                        <Form.Label>Status</Form.Label>
                        <Form.Select value={status} onChange={(e) => setStatus(e.target.value)}>
                            <option value="todo">To Do</option>
                            <option value="in-progress">In Progress</option>
                            <option value="completed">Completed</option>
                        </Form.Select>
                    </Form.Group>
                    <Form.Group className="mb-3" controlId="formDueDate">
                        <Form.Label>Due Date</Form.Label>
                        <Form.Control
                            type="datetime-local"
                            value={dueDate}
                            onChange={(e) => setDueDate(e.target.value)}
                            required
                        />
                    </Form.Group>
                    <Form.Group className="mb-3" controlId="formTaskFile">
                        <Form.Label>Attach File</Form.Label>
                        <Form.Control type="file" onChange={handleFileChange} />
                    </Form.Group>
                    <Button variant="primary" type="submit">
                        Add Task
                    </Button>
                </Form>
            </Modal.Body>
        </Modal>
    );
};

export default AddTaskModal;

