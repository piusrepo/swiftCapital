const express = require('express');
require('dotenv').config();
// const multer = require('multer');
const cookieParser = require('cookie-parser');
const methodOverride = require('method-override');
const session = require('express-session');
const flash = require('connect-flash');
const cors = require('cors');
const path = require('path');
const { requireAuth, checkUser } = require('./server/authMiddleware/authMiddleware');
const connectDB = require('./server/config/db');

const app = express();
const PORT = process.env.PORT || 7000;

// Connect to Database
connectDB();

// Middlewares
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// app.use(upload.none()); 
app.use(cookieParser());
app.use(cors());
app.use(methodOverride('_method'));
app.use(
  session({
    secret: 'piuscandothis',
    resave: false,
    saveUninitialized: false,
  })
);
app.use(flash());

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  next();
});


// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  req.flash('error', err.message || 'Something went wrong!');
  res.redirect('back');
});

// Middleware to pass flash messages to views
app.use((req, res, next) => {
  res.locals.messages = req.flash();
  next();
});


// Set view engine
app.set('view engine', 'ejs');

// Routes
app.get('*', checkUser);
app.use('/', require('./server/Route/indexRoute'));
app.use('/', requireAuth, require('./server/Route/userRoute'));
app.use('/', requireAuth, require('./server/Route/adminRoute'));

// Start server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));