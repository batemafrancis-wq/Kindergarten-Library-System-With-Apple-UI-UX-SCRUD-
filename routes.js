const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
// Models
const mongoose = require('mongoose');

// User Schema
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  username: {
    type: String,
    required: true,
    unique: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    enum: ['student', 'teacher', 'librarian', 'admin'],
    default: 'student',
  },
}, {
  timestamps: true,
});

// Password comparison method
userSchema.methods.matchPassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Book Schema
const bookSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
  },
  author: {
    type: String,
    required: true,
  },
  isbn: {
    type: String,
    required: true,
    unique: true,
  },
  subject: {
    type: String,
    required: true,
  },
  summary: {
    type: String,
  },
  totalCopies: {
    type: Number,
    default: 1,
  },
  availableCopies: {
    type: Number,
    default: 1,
  },
  borrowers: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
    borrowDate: {
      type: Date,
      default: Date.now,
    },
    dueDate: {
      type: Date,
      required: true,
    },
  }],
}, {
  timestamps: true,
});

// BorrowRecord Schema
const borrowRecordSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  book: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Book',
    required: true,
  },
  borrowDate: {
    type: Date,
    default: Date.now,
  },
  dueDate: {
    type: Date,
    required: true,
  },
  returnDate: {
    type: Date,
  },
  status: {
    type: String,
    enum: ['borrowed', 'returned', 'overdue'],
    default: 'borrowed',
  },
  renewed: {
    type: Boolean,
    default: false,
  },
}, {
  timestamps: true,
});

// Log Schema
const logSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  action: {
    type: String,
    required: true,
  },
  details: {
    type: String,
  },
  timestamp: {
    type: Date,
    default: Date.now,
  },
}, {
  timestamps: true,
});

// Models
const User = mongoose.model('User', userSchema);
const Book = mongoose.model('Book', bookSchema);
const BorrowRecord = mongoose.model('BorrowRecord', borrowRecordSchema);
const Log = mongoose.model('Log', logSchema);

// Middleware functions
const protect = async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    try {
      token = req.headers.authorization.split(' ')[1];

      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      req.user = await User.findById(decoded.id).select('-password');

      next();
    } catch (error) {
      console.error(error);
      res.status(401).json({ message: 'Not authorized, token failed' });
    }
  }

  if (!token) {
    res.status(401).json({ message: 'Not authorized, no token' });
  }
};

const authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        message: `User role ${req.user.role} is not authorized to access this route`,
      });
    }
    next();
  };
};

// Auth Routes
const authRouter = express.Router();

// @route   POST /api/auth/register
// @desc    Register user
// @access  Public
authRouter.post(
  '/register',
  [
    body('name', 'Name is required').not().isEmpty(),
    body('username', 'Username is required').not().isEmpty(),
    body('email', 'Please include a valid email').isEmail(),
    body('password', 'Password must be 6 or more characters').isLength({ min: 6 }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, username, email, password, role } = req.body;

    try {
      let user = await User.findOne({ $or: [{ email }, { username }] });

      if (user) {
        return res.status(400).json({ message: 'User already exists' });
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      user = new User({
        name,
        username,
        email,
        password: hashedPassword,
        role: role || 'student', // Default to student
      });

      await user.save();

      const payload = {
        id: user._id,
      };

      jwt.sign(
        payload,
        process.env.JWT_SECRET,
        { expiresIn: '30d' },
        (err, token) => {
          if (err) throw err;
          res.json({
            token,
            user: {
              id: user._id,
              name: user.name,
              username: user.username,
              email: user.email,
              role: user.role,
            },
          });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  }
);

// @route   POST /api/auth/login
// @desc    Authenticate user & get token
// @access  Public
authRouter.post(
  '/login',
  [
    body('username', 'Username is required').not().isEmpty(),
    body('password', 'Password is required').exists(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;

    try {
      const user = await User.findOne({ username });

      if (!user) {
        return res.status(400).json({ message: 'Invalid credentials' });
      }

      const isMatch = await user.matchPassword(password);

      if (!isMatch) {
        return res.status(400).json({ message: 'Invalid credentials' });
      }

      const payload = {
        id: user._id,
      };

      jwt.sign(
        payload,
        process.env.JWT_SECRET,
        { expiresIn: '30d' },
        (err, token) => {
          if (err) throw err;
          res.json({
            token,
            user: {
              id: user._id,
              name: user.name,
              username: user.username,
              email: user.email,
              role: user.role,
            },
          });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  }
);

// @route   GET /api/auth/profile
// @desc    Get current user profile
// @access  Private
authRouter.get('/profile', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    res.json(user);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Books Routes
const booksRouter = express.Router();

// @route   GET /api/books
// @desc    Get all books with optional search
// @access  Private
booksRouter.get('/', protect, async (req, res) => {
  try {
    const { search } = req.query;
    let query = {};

    if (search) {
      query = {
        $or: [
          { title: { $regex: search, $options: 'i' } },
          { author: { $regex: search, $options: 'i' } },
          { subject: { $regex: search, $options: 'i' } },
        ],
      };
    }

    const books = await Book.find(query).sort({ createdAt: -1 });
    res.json(books);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// @route   GET /api/books/overdue
// @desc    Get overdue books
// @access  Private (Librarian/Admin)
booksRouter.get('/overdue', [protect, authorize('librarian', 'admin')], async (req, res) => {
  try {
    const currentDate = new Date();
    const overdueBooks = await Book.find({
      'borrowers.dueDate': { $lt: currentDate },
      'borrowers': { $exists: true, $ne: [] }
    }).populate('borrowers.user', 'name email');

    res.json(overdueBooks);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// @route   GET /api/books/:id
// @desc    Get book by ID
// @access  Private
booksRouter.get('/:id', protect, async (req, res) => {
  try {
    const book = await Book.findById(req.params.id);

    if (!book) {
      return res.status(404).json({ message: 'Book not found' });
    }

    res.json(book);
  } catch (err) {
    console.error(err.message);
    if (err.kind === 'ObjectId') {
      return res.status(404).json({ message: 'Book not found' });
    }
    res.status(500).send('Server error');
  }
});

// @route   POST /api/books
// @desc    Add new book
// @access  Private (Librarian/Admin)
booksRouter.post(
  '/',
  [
    protect,
    authorize('librarian', 'admin', 'teacher'),
    [
      body('title', 'Title is required').not().isEmpty(),
      body('author', 'Author is required').not().isEmpty(),
      body('isbn', 'ISBN is required').not().isEmpty(),
      body('subject', 'Subject is required').not().isEmpty(),
    ],
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { title, author, isbn, subject, summary, copies } = req.body;

    try {
      let book = await Book.findOne({ isbn });

      if (book) {
        return res.status(400).json({ message: 'Book with this ISBN already exists' });
      }

      book = new Book({
        title,
        author,
        isbn,
        subject,
        summary,
        totalCopies: copies || 1,
        availableCopies: copies || 1,
      });

      await book.save();

      // Log the action
      await Log.create({
        user: req.user._id,
        action: 'Book Added',
        details: `Added book: ${title} by ${author}`,
      });

      // Emit socket event
      const io = req.app.get('io');
      io.emit('bookCreated', book);

      res.json(book);
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  }
);

// @route   PUT /api/books/:id
// @desc    Update book
// @access  Private (Librarian/Admin)
booksRouter.put(
  '/:id',
  [
    protect,
    authorize('librarian', 'admin', 'teacher'),
    [
      body('title', 'Title is required').not().isEmpty(),
      body('author', 'Author is required').not().isEmpty(),
      body('isbn', 'ISBN is required').not().isEmpty(),
      body('subject', 'Subject is required').not().isEmpty(),
    ],
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { title, author, isbn, subject, summary, copies } = req.body;

    try {
      let book = await Book.findById(req.params.id);

      if (!book) {
        return res.status(404).json({ message: 'Book not found' });
      }

      // Check if ISBN is being changed and if it conflicts
      if (isbn !== book.isbn) {
        const existingBook = await Book.findOne({ isbn });
        if (existingBook) {
          return res.status(400).json({ message: 'Book with this ISBN already exists' });
        }
      }

      book.title = title;
      book.author = author;
      book.isbn = isbn;
      book.subject = subject;
      book.summary = summary;
      book.totalCopies = copies || book.totalCopies;
      book.availableCopies = Math.min(book.availableCopies, copies || book.totalCopies);

      await book.save();

      // Log the action
      await Log.create({
        user: req.user._id,
        action: 'Book Updated',
        details: `Updated book: ${title} by ${author}`,
      });

      // Emit socket event
      const io = req.app.get('io');
      io.emit('bookUpdated', book);

      res.json(book);
    } catch (err) {
      console.error(err.message);
      if (err.kind === 'ObjectId') {
        return res.status(404).json({ message: 'Book not found' });
      }
      res.status(500).send('Server error');
    }
  }
);

// @route   DELETE /api/books/:id
// @desc    Delete book
// @access  Private (Librarian/Admin)
booksRouter.delete('/:id', [protect, authorize('librarian', 'admin', 'teacher')], async (req, res) => {
  try {
    const book = await Book.findById(req.params.id);

    if (!book) {
      return res.status(404).json({ message: 'Book not found' });
    }

    // Check if book is currently borrowed
    if (book.borrowers.length > 0) {
      return res.status(400).json({ message: 'Cannot delete book that is currently borrowed' });
    }

    await Book.findByIdAndDelete(req.params.id);

    // Log the action
    await Log.create({
      user: req.user._id,
      action: 'Book Deleted',
      details: `Deleted book: ${book.title} by ${book.author}`,
    });

    // Emit socket event
    const io = req.app.get('io');
    io.emit('bookDeleted', req.params.id);

    res.json({ message: 'Book removed' });
  } catch (err) {
    console.error(err.message);
    if (err.kind === 'ObjectId') {
      return res.status(404).json({ message: 'Book not found' });
    }
    res.status(500).send('Server error');
  }
});

// @route   POST /api/books/borrow/:bookId
// @desc    Borrow a book
// @access  Private
booksRouter.post('/borrow/:bookId', protect, async (req, res) => {
  try {
    const book = await Book.findById(req.params.bookId);

    if (!book) {
      return res.status(404).json({ message: 'Book not found' });
    }

    if (book.availableCopies <= 0) {
      return res.status(400).json({ message: 'Book is not available' });
    }

    // Check if user already has this book borrowed
    const alreadyBorrowed = book.borrowers.some(borrower => borrower.user.toString() === req.user._id.toString());
    if (alreadyBorrowed) {
      return res.status(400).json({ message: 'You have already borrowed this book' });
    }

    // Calculate due date (14 days from now)
    const dueDate = new Date();
    dueDate.setDate(dueDate.getDate() + 14);

    // Add to borrowers
    book.borrowers.push({
      user: req.user._id,
      borrowDate: new Date(),
      dueDate,
    });

    book.availableCopies -= 1;
    await book.save();

    // Create BorrowRecord
    await BorrowRecord.create({
      user: req.user._id,
      book: req.params.bookId,
      borrowDate: new Date(),
      dueDate,
      status: 'borrowed',
    });

    // Log the action
    await Log.create({
      user: req.user._id,
      action: 'Book Borrowed',
      details: `Borrowed: ${book.title} by ${book.author}`,
    });

    // Emit socket event
    const io = req.app.get('io');
    io.emit('bookBorrowed', { book, userId: req.user._id });

    res.json({ message: 'Book borrowed successfully', dueDate });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// @route   POST /api/books/return/:bookId
// @desc    Return a book
// @access  Private
booksRouter.post('/return/:bookId', protect, async (req, res) => {
  try {
    const book = await Book.findById(req.params.bookId);

    if (!book) {
      return res.status(404).json({ message: 'Book not found' });
    }

    // Find the borrower
    const borrowerIndex = book.borrowers.findIndex(borrower => borrower.user.toString() === req.user._id.toString());
    if (borrowerIndex === -1) {
      return res.status(400).json({ message: 'You have not borrowed this book' });
    }

    // Remove from borrowers
    book.borrowers.splice(borrowerIndex, 1);
    book.availableCopies += 1;
    await book.save();

    // Update BorrowRecord
    const borrowRecord = await BorrowRecord.findOne({
      user: req.user._id,
      book: req.params.bookId,
      status: 'borrowed',
    }).sort({ createdAt: -1 });

    if (borrowRecord) {
      borrowRecord.returnDate = new Date();
      borrowRecord.status = 'returned';
      await borrowRecord.save();
    }

    // Log the action
    await Log.create({
      user: req.user._id,
      action: 'Book Returned',
      details: `Returned: ${book.title} by ${book.author}`,
    });

    // Emit socket event
    const io = req.app.get('io');
    io.emit('bookReturned', { book, userId: req.user._id });

    res.json({ message: 'Book returned successfully' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Borrow Routes
const borrowRouter = express.Router();

// @route   POST /api/borrow
// @desc    Borrow a book
// @access  Private
borrowRouter.post('/', protect, async (req, res) => {
  const { bookId } = req.body;

  try {
    const book = await Book.findById(bookId);

    if (!book) {
      return res.status(404).json({ message: 'Book not found' });
    }

    if (book.availableCopies <= 0) {
      return res.status(400).json({ message: 'Book is not available' });
    }

    // Check if user already has this book borrowed
    const existingBorrow = await BorrowRecord.findOne({
      user: req.user._id,
      book: bookId,
      status: 'borrowed',
    });

    if (existingBorrow) {
      return res.status(400).json({ message: 'You have already borrowed this book' });
    }

    // Calculate due date (14 days from now)
    const dueDate = new Date();
    dueDate.setDate(dueDate.getDate() + 14);

    const borrowRecord = new BorrowRecord({
      user: req.user._id,
      book: bookId,
      dueDate,
    });

    await borrowRecord.save();

    // Update book available copies
    book.availableCopies -= 1;
    await book.save();

    // Log the action
    await Log.create({
      user: req.user._id,
      action: 'Book Borrowed',
      details: `Borrowed: ${book.title} by ${book.author}`,
    });

    // Emit socket event
    const io = req.app.get('io');
    io.emit('bookBorrowed', { book, borrowRecord });

    res.json(borrowRecord);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// @route   GET /api/borrow
// @desc    Get user's borrow records
// @access  Private
borrowRouter.get('/', protect, async (req, res) => {
  try {
    const borrowRecords = await BorrowRecord.find({ user: req.user._id })
      .populate('book')
      .sort({ createdAt: -1 });

    res.json(borrowRecords);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// @route   PUT /api/borrow/:id/renew
// @desc    Renew borrow
// @access  Private
borrowRouter.put('/:id/renew', protect, async (req, res) => {
  try {
    const borrowRecord = await BorrowRecord.findById(req.params.id);

    if (!borrowRecord) {
      return res.status(404).json({ message: 'Borrow record not found' });
    }

    if (borrowRecord.user.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Not authorized' });
    }

    if (borrowRecord.status !== 'borrowed') {
      return res.status(400).json({ message: 'Book is not currently borrowed' });
    }

    if (borrowRecord.renewed) {
      return res.status(400).json({ message: 'Book has already been renewed' });
    }

    // Extend due date by 14 days
    const newDueDate = new Date(borrowRecord.dueDate);
    newDueDate.setDate(newDueDate.getDate() + 14);

    borrowRecord.dueDate = newDueDate;
    borrowRecord.renewed = true;

    await borrowRecord.save();

    // Log the action
    await Log.create({
      user: req.user._id,
      action: 'Book Renewed',
      details: `Renewed borrow for book ID: ${borrowRecord.book}`,
    });

    res.json(borrowRecord);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// @route   DELETE /api/borrow/:id
// @desc    Cancel borrow (before pickup or something, but here it's to cancel pending)
// @access  Private
borrowRouter.delete('/:id', protect, async (req, res) => {
  try {
    const borrowRecord = await BorrowRecord.findById(req.params.id);

    if (!borrowRecord) {
      return res.status(404).json({ message: 'Borrow record not found' });
    }

    if (borrowRecord.user.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Not authorized' });
    }

    if (borrowRecord.status !== 'borrowed') {
      return res.status(400).json({ message: 'Cannot cancel returned book' });
    }

    // Update book available copies
    const book = await Book.findById(borrowRecord.book);
    if (book) {
      book.availableCopies += 1;
      await book.save();
    }

    await BorrowRecord.findByIdAndDelete(req.params.id);

    // Log the action
    await Log.create({
      user: req.user._id,
      action: 'Borrow Cancelled',
      details: `Cancelled borrow for book ID: ${borrowRecord.book}`,
    });

    // Emit socket event
    const io = req.app.get('io');
    io.emit('borrowCancelled', { book, borrowId: req.params.id });

    res.json({ message: 'Borrow cancelled' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// @route   PUT /api/borrow/:id/return
// @desc    Return book
// @access  Private
borrowRouter.put('/:id/return', protect, async (req, res) => {
  try {
    const borrowRecord = await BorrowRecord.findById(req.params.id).populate('book').populate('user', 'name');

    if (!borrowRecord) {
      return res.status(404).json({ message: 'Borrow record not found' });
    }

    // Check if user is the borrower or has librarian/admin role
    if (borrowRecord.user.toString() !== req.user._id.toString() && !['librarian', 'admin'].includes(req.user.role)) {
      return res.status(403).json({ message: 'Not authorized to return this book' });
    }

    if (borrowRecord.status !== 'borrowed') {
      return res.status(400).json({ message: 'Book is not currently borrowed' });
    }

    borrowRecord.returnDate = new Date();
    borrowRecord.status = 'returned';

    await borrowRecord.save();

    // Update book available copies
    const book = await Book.findById(borrowRecord.book);
    if (book) {
      book.availableCopies += 1;
      await book.save();
    }

    // Log the action
    await Log.create({
      user: req.user._id,
      action: 'Book Returned',
      details: `Returned: ${book.title} by ${book.author} for user ${borrowRecord.user.name}`,
    });

    // Emit socket event
    const io = req.app.get('io');
    io.emit('bookReturned', { book, borrowRecord });

    res.json(borrowRecord);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Users Routes
const usersRouter = express.Router();

// @route   GET /api/users
// @desc    Get all users
// @access  Private (Admin)
usersRouter.get('/', [protect, authorize('admin')], async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    res.json(users);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// @route   POST /api/users
// @desc    Create user
// @access  Private (Admin)
usersRouter.post(
  '/',
  [
    protect,
    authorize('admin'),
    [
      body('name', 'Name is required').not().isEmpty(),
      body('email', 'Please include a valid email').isEmail(),
      body('password', 'Password must be 6 or more characters').isLength({ min: 6 }),
      body('role', 'Role is required').isIn(['student', 'teacher', 'librarian', 'admin']),
    ],
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password, role } = req.body;

    try {
      let user = await User.findOne({ email });

      if (user) {
        return res.status(400).json({ message: 'User already exists' });
      }

      user = new User({
        name,
        email,
        password,
        role,
      });

      await user.save();

      // Log the action
      await Log.create({
        user: req.user._id,
        action: 'User Created',
        details: `Created user: ${name} (${email}) with role: ${role}`,
      });

      // Emit socket event
      const io = req.app.get('io');
      io.emit('userCreated', user);

      res.json({
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      });
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  }
);

// @route   PUT /api/users/:id
// @desc    Update user
// @access  Private (Admin)
usersRouter.put(
  '/:id',
  [
    protect,
    authorize('admin'),
    [
      body('name', 'Name is required').not().isEmpty(),
      body('email', 'Please include a valid email').isEmail(),
      body('role', 'Role is required').isIn(['student', 'teacher', 'librarian', 'admin']),
    ],
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, role } = req.body;

    try {
      let user = await User.findById(req.params.id);

      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      // Check if email is being changed and if it conflicts
      if (email !== user.email) {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
          return res.status(400).json({ message: 'User with this email already exists' });
        }
      }

      user.name = name;
      user.email = email;
      user.role = role;

      await user.save();

      // Log the action
      await Log.create({
        user: req.user._id,
        action: 'User Updated',
        details: `Updated user: ${name} (${email}) role: ${role}`,
      });

      // Emit socket event
      const io = req.app.get('io');
      io.emit('userUpdated', user);

      res.json({
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      });
    } catch (err) {
      console.error(err.message);
      if (err.kind === 'ObjectId') {
        return res.status(404).json({ message: 'User not found' });
      }
      res.status(500).send('Server error');
    }
  }
);

// @route   DELETE /api/users/:id
// @desc    Delete user
// @access  Private (Admin)
usersRouter.delete('/:id', [protect, authorize('admin')], async (req, res) => {
  try {
    const user = await User.findById(req.params.id);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Prevent deleting self
    if (user._id.toString() === req.user._id.toString()) {
      return res.status(400).json({ message: 'Cannot delete your own account' });
    }

    // Check if user has active borrows
    const activeBorrows = await BorrowRecord.find({
      user: req.params.id,
      status: 'borrowed',
    });

    if (activeBorrows.length > 0) {
      return res.status(400).json({ message: 'Cannot delete user with active borrows' });
    }

    await User.findByIdAndDelete(req.params.id);

    // Log the action
    await Log.create({
      user: req.user._id,
      action: 'User Deleted',
      details: `Deleted user: ${user.name} (${user.email})`,
    });

    // Emit socket event
    const io = req.app.get('io');
    io.emit('userDeleted', req.params.id);

    res.json({ message: 'User removed' });
  } catch (err) {
    console.error(err.message);
    if (err.kind === 'ObjectId') {
      return res.status(404).json({ message: 'User not found' });
    }
    res.status(500).send('Server error');
  }
});

// @route   GET /api/users/:userId/borrowed
// @desc    Get borrow records for user
// @access  Private
usersRouter.get('/:userId/borrowed', protect, async (req, res) => {
  try {
    // Check if user is requesting their own data or is admin
    if (req.params.userId !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Not authorized' });
    }

    const borrowRecords = await BorrowRecord.find({
      user: req.params.userId,
      status: 'borrowed',
    }).populate('book').sort({ createdAt: -1 });

    res.json(borrowRecords);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Logs Routes
const logsRouter = express.Router();

// @route   GET /api/logs
// @desc    Get all logs
// @access  Private (Librarian/Admin)
logsRouter.get('/', [protect, authorize('librarian', 'admin')], async (req, res) => {
  try {
    const logs = await Log.find()
      .populate('user', 'name email')
      .sort({ timestamp: -1 });

    res.json(logs);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

module.exports = {
  auth: authRouter,
  books: booksRouter,
  borrow: borrowRouter,
  users: usersRouter,
  logs: logsRouter,
  User,
  Book,
  BorrowRecord,
  Log,
};