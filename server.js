const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const { User, Book, BorrowRecord, Log } = require('./routes');
const routes = require('./routes');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI);

    console.log(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
};

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "http://localhost:2050",
    methods: ["GET", "POST"]
  }
});

// Connect to database
connectDB();

// Create default admin user
const createDefaultAdmin = async () => {
  try {
    const adminExists = await User.findOne({ role: 'admin' });
    if (!adminExists) {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash('test123', salt);
      await User.collection.insertOne({
        name: 'Admin Test',
        username: 'admintest',
        email: 'admin@test.com',
        password: hashedPassword,
        role: 'admin',
        createdAt: new Date(),
        updatedAt: new Date(),
      });
      console.log('Default admin user created: admintest / test123');
    }
  } catch (error) {
    console.error('Error creating default admin:', error);
  }
};

createDefaultAdmin();

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use('/api/auth', routes.auth);
app.use('/api/books', routes.books);
app.use('/api/borrow', routes.borrow);
app.use('/api/users', routes.users);
app.use('/api/logs', routes.logs);

// Clear all data route (for development)
app.delete('/api/clear', async (req, res) => {
  try {
    await User.deleteMany({});
    await Book.deleteMany({});
    await BorrowRecord.deleteMany({});
    await Log.deleteMany({});
    res.json({ message: 'All data cleared successfully' });
  } catch (error) {
    console.error('Error clearing data:', error);
    res.status(500).json({ message: 'Failed to clear data' });
  }
});

// Socket.io
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

// Make io accessible in routes
app.set('io', io);

const PORT = process.env.PORT || 5001;

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});