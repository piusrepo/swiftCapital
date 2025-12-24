const express = require('express');
const session = require('express-session');
const flash = require('connect-flash');
const fileUpload = require('express-fileupload');
const cookieParser = require('cookie-parser');
const methodOverride = require('method-override');
const { requireAuth, checkUser } = require('./server/authMiddleware/authMiddleware');
const connectDB = require('./server/config/db');

const app = express();
const PORT = process.env.PORT || 7000;

// Connect to Database
connectDB();

// Middlewares
app.use(express.static('public'));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());
app.use(fileUpload());
app.use(methodOverride('_method'));

// Session and Flash Configuration
app.use(
  session({
    secret: 'CookingBlogSecretSession',
    saveUninitialized: false, // Set to false to avoid creating sessions for unauthenticated users
    resave: false, // Set to false to prevent resaving session if not modified
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 hours
  })
);
app.use(flash());

// Make flash messages available to all views
app.use((req, res, next) => {
  res.locals.success_msg = req.flash('infoSubmit'); // Success messages
  res.locals.error_msg = req.flash('infoErrors');   // Error messages
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