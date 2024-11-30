const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const jwtSecret = process.env.JWT_SECRET || 'fallback_secret_key';



const app = express();
// app.use(cors());
app.use(cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
}));
app.use(express.json());

const PORT = process.env.PORT || 10000;


// Multer setup for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    },
});
// const upload = multer({ storage }); // Multer middleware instance

// User schema
const schemaData = mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
    },
    password: {
        type: String,
        required: true,
        minlength: 6,
    },
    role: {
        type: String,
        required: true,
    },
    title: {
        type: String,
        required: true,
    },
    admin: {
        type: Boolean,
        default: false,
    }
}, {
    timestamps: true
});

// Pre-save hook to hash password before saving
schemaData.pre('save', async function (next) {
    if (!this.isModified('password')) return next(); // Don't hash if the password hasn't changed
    try {
        // Hash the password with bcryptjs
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

const userModel = mongoose.model("user", schemaData);

// Task schema
const taskSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
        trim: true,
    },
    description: {
        type: String,
        trim: true,
    },
    assignedUsers: [
        {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'user',
        },
    ],
    status: {
        type: String,
        enum: ['todo', 'in progress', 'done'],
        default: 'todo',
    },
    dueDate: {
        type: Date,
        required: true,
    },
    files: [
        {
            filename: { type: String },
            path: { type: String },
            uploadedAt: { type: Date, default: Date.now },
        },
    ],
    // Add the user who created the task
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'user',
        required: true,
    },
});

const taskModel = mongoose.model("Task", taskSchema);

// READ: Get all users
app.get("/", async (req, res) => {
    try {
        const data = await userModel.find({});
        res.status(200).json({ Success: true, data: data });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Generate JWT Token
function generateToken(userId, name) {
    return jwt.sign({ id: userId, name }, jwtSecret, { expiresIn: '24h' });
}

// Register a user
app.post("/register", async (req, res) => {
    try {
        const { name, email, password, role, title, admin } = req.body;

        // Check if the user already exists
        const existingUser = await userModel.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Create a new user
        const data = new userModel(req.body);
        await data.save();

        // Generate JWT token and send it back to the user
        const token = generateToken(data._id);

        res.status(201).json({
            message: 'User registered successfully',
            token: token, // Send token to the client
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Login a user
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if the user exists
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        // Compare the provided password with the stored hashed password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        // Generate JWT token and send it back
        const token = generateToken(user._id, user.name);

        res.status(200).json({
            message: 'Login successful',
            token: token, // Send token to the client
            user: { id: user._id, name: user.name, email: user.email }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});


// Update user
app.put("/update/:id", async (req, res) => {
    try {
        const id = req.params.id;
        const userExist = await userModel.findOne({ _id: id });

        if (!userExist) {
            return res.status(404).json({ message: `User with id:${id} not found.` });
        }
        const updateUser = await userModel.findByIdAndUpdate(id, req.body, { new: true });
        res.status(200).json(updateUser);
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Delete user
app.delete("/delete/:id", async (req, res) => {
    try {
        const id = req.params.id;
        const userExist = await userModel.findOne({ _id: id });

        if (!userExist) {
            return res.status(404).json({ message: `User with id:${id} not found.` });
        }
        await userModel.findByIdAndDelete(id);
        res.status(200).json({ message: `User with id:${id} deleted successfully.` });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.post("/logout", (req, res) => {
    res.status(200).json({ message: 'Logged out successfully' });
});

// Middleware to authenticate the user
// const authenticateUser = (req, res, next) => {
//     // Get the token from the 'Authorization' header
//     const token = req.headers['authorization']?.split(' ')[1];

//     if (!token) {
//         return res.status(401).json({ message: 'No token provided, authentication failed' });
//     }

//     // Verify the token
//     jwt.verify(token, jwtSecret, (err, decoded) => {
//         if (err) {

//             return res.status(401).json({ message: 'Invalid token' });
//         }
//         req.userId = decoded.userId; // Store userId in request object
//         next(); // Proceed to the next middleware or route handler
//     });
// };

const authenticateUser = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];

    console.log('Token-=========->', token); // Debugging line to check the token

    if (!token) {
        return res.status(401).json({ message: 'No token provided, authentication failed' });
    }

    jwt.verify(token, jwtSecret, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Invalid token' });
        }

        console.log('Decoded JWT:', decoded); // Debugging line to check decoded JWT

        req.userId = decoded.id;
        next();
    });
};


// TASK: Create a task
app.post('/create', authenticateUser, upload.array('files', 5), async (req, res) => {
    try {
        const { title, description, assignedUsers, status, dueDate, createdBy } = req.body;

        // Validate `assignedUsers`
        if (!assignedUsers || !Array.isArray(JSON.parse(assignedUsers))) {
            return res.status(400).json({
                message: "Error: `assignedUsers` must be a valid array of user IDs.",
            });
        }
        // Parse stringified array
        const userEmails = JSON.parse(assignedUsers);

        // Validate email format
        if (!userEmails.every(email => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) {
            return res.status(400).json({ message: "Error: One or more emails are invalid." });
        }

        // Resolve emails to user IDs
        const users = await userModel.find({ email: { $in: userEmails } });
        if (users.length !== userEmails.length) {
            return res.status(404).json({ message: "Error: One or more emails do not belong to valid users." });
        }
        const userIds = users.map(user => user._id);

        // Validate `req.files`
        const files = req.files ? req.files.map((file) => ({
            filename: file.originalname,
            path: file.path,
        })) : [];

        // Create task with `createdBy` field
        const task = new taskModel({
            title,
            description,
            assignedUsers: userIds,
            status,
            dueDate,
            files,
            createdBy: req.userId,
        });

        await task.save();
        res.status(201).json({ message: 'Task created successfully', task });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error creating task', error: error.message });
    }
});



// TASK: task list
app.get('/tasks/:userId', async (req, res) => {
    try {
        // const userId = req.params.userId;
        const userId = req.params.userId;

        if (!userId) {
            return res.status(400).json({ error: 'User ID is required' });
        }

        const tasks = await taskModel.find({ createdBy: userId }).populate('assignedUsers');

        if (tasks.length === 0) {
            return res.status(404).json({ error: `No tasks found for user with ID ${userId}` });
        }

        // Format the tasks to include only the desired fields
        const formattedTasks = tasks.map(task => ({
            _id: task._id,
            title: task.title,
            description: task.description,
            status: task.status,
            dueDate: task.dueDate,
            files: task.files,
            assignedUsers: task.assignedUsers.map(user => ({
                _id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
                title: user.title,
                createdAt: user.createdAt,
                updatedAt: user.updatedAt
            }))

        }));


        res.status(200).json({ success: true, tasks: formattedTasks });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error fetching tasks', error: error.message });
    }
});

// Task Assigned to a user by other users
app.get('/tasks/assigned/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;

        if (!userId) {
            return res.status(400).json({ error: 'User ID is required' });
        }

        // Query to find tasks where the user is assigned but did not create the task
        const tasks = await taskModel.find({
            assignedUsers: userId,     // The user is in the assignedUsers array
            createdBy: { $ne: userId } // The user is NOT the creator of the task
        }).populate('assignedUsers');

        if (tasks.length === 0) {
            return res.status(404).json({ error: `No tasks assigned to user with ID ${userId} by others` });
        }

        // Format the tasks to include only the desired fields
        const formattedTasks = tasks.map(task => ({
            _id: task._id,
            title: task.title,
            description: task.description,
            status: task.status,
            dueDate: task.dueDate,
            files: task.files,
            assignedUsers: task.assignedUsers.map(user => ({
                _id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
                title: user.title,
                createdAt: user.createdAt,
                updatedAt: user.updatedAt
            }))
        }));

        res.status(200).json({ success: true, tasks: formattedTasks });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error fetching assigned tasks', error: error.message });
    }
});




// UPDATE: task update
app.put('/task/:taskId', authenticateUser, upload.array('files', 5), async (req, res) => {
    try {
        // Extract taskId from request parameters
        const taskId = req.params.taskId;
        // Extract data from request body
        const { title, description, assignedUsers, status, dueDate } = req.body;

        // Prepare fields to update
        let updatedFields = { title, description, status, dueDate };

        // Handle `assignedUsers` if provided
        if (assignedUsers) {
            if (!Array.isArray(JSON.parse(assignedUsers))) {
                return res.status(400).json({
                    message: "`assignedUsers` must be a valid array of user IDs.",
                });
            }
            updatedFields.assignedUsers = JSON.parse(assignedUsers);
        }

        // Handle file uploads if provided
        if (req.files && req.files.length > 0) {
            const files = req.files.map((file) => ({
                filename: file.originalname,
                path: file.path,
            }));
            // Add uploaded files to the update
            updatedFields.files = files;
        }

        // Update the task
        const updatedTask = await taskModel.findByIdAndUpdate(
            taskId,
            { $set: updatedFields },
            // Return the updated document
            { new: true }
        );

        if (!updatedTask) {
            return res.status(404).json({ message: `Task with ID ${taskId} not found` });
        }

        res.status(200).json({
            message: "Task updated successfully",
            task: updatedTask,
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error updating task", error: error.message });
    }
});

// DELETE: task delete
app.delete('/task/:taskId', authenticateUser, async (req, res) => {
    try {
        const taskId = req.params.taskId; // Extract taskId from request parameters

        // Find the task and delete it
        const deletedTask = await taskModel.findByIdAndDelete(taskId);

        if (!deletedTask) {
            return res.status(404).json({
                message: `Task with ID ${taskId} not found`,
            });
        }

        // Optionally, handle file deletion from the file system
        if (deletedTask.files && deletedTask.files.length > 0) {
            const fs = require('fs');
            deletedTask.files.forEach((file) => {
                if (fs.existsSync(file.path)) {
                    fs.unlinkSync(file.path);
                }
            });
        }

        res.status(200).json({
            message: "Task deleted successfully",
            task: deletedTask,
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error deleting task", error: error.message });
    }
});





















// Connect to MongoDB and start the server
mongoose.connect("mongodb+srv://user:giVERWu3LjVd8DqY@crudeoperation.elaii.mongodb.net/")
    .then(() => console.log("Connected to Database"))
    .catch((error) => console.log("DB connection error:", error));

app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
