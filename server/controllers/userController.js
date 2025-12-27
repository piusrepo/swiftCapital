const User = require('../Model/User');
const Deposit = require('../Model/depositSchema');
const Depositdetails = require("../Model/depositDetails");
const Signal = require("../Model/loan");
const Verify = require("../Model/support");
const transferMoney = require("../Model/Transfer");
const Loan = require("../Model/loan");
const Ticket = require("../Model/support");
const crypto = require("crypto")
const jwt = require('jsonwebtoken');
const { Resend } = require('resend');
const resend = new Resend(process.env.RESEND_API_KEY);
const fsPromises = require('fs').promises;
const cloudinary = require('cloudinary').v2;

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Generate verification URL dynamically
const generateVerificationUrl = (verificationToken) => {
  const baseUrl = process.env.BASE_URL || 'http://localhost:7000';
  return `${baseUrl}/verify-email?user=${verificationToken}&ver_code=${verificationToken}`;
};

// Send verification email using Resend
const sendVerificationEmail = async (email, firstname,lastname, verificationToken) => {
  const verificationUrl = generateVerificationUrl(verificationToken);

  try {
    const { data, error } = await resend.emails.send({
      from: 'Support <support@swiftcaptial.com>',
      to: [email],
      subject: 'Verify Your Email - Swift Capital',
      html: `
        <div style="background-color: #1C2526; padding: 20px; font-family: Arial, sans-serif; color: #F5F6F5; text-align: center; max-width: 600px; margin: 0 auto;">
          <!-- Header -->
          <div style="background-color: #2E3A3B; padding: 15px; border-bottom: 2px solid #F5F6F5;">
            <img src="https://swiftcaptial.com/assets/img/gkgr73S0C0AVl3XX0UUQh8Ffr0fmzCSK4EhmlcPQ.jpg" alt="Swift Capital Logo" style="max-width: 150px; height: auto; display: block; margin: 0 auto;">
            <h2 style="color: #F5F6F5; margin: 10px 0 0; font-size: 24px;">Verify Your Email Account</h2>
          </div>
          <!-- Body -->
          <div style="padding: 20px; font-size: 16px; line-height: 1.5;">
            <p>Hi ${firstname}${lastname},</p>
            <p style="color: #F5F6F5;">Thanks for creating an account with us at Swift Capital. Please click the button below to verify your account:</p>
            <a href="${verificationUrl}" style="display: inline-block; padding: 12px 24px; background-color: #3F3EED; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0;">Confirm Email</a>
            <p style="color: #F5F6F5;">If the button above doesn't work, please copy and paste this link into your browser:</p>
            <p><a href="${verificationUrl}" style="color: #4A90E2; text-decoration: none;">${verificationUrl}</a></p>
    
          <!-- Footer -->
          <div style="background-color: #2E3A3B; padding: 15px; border-top: 2px solid #F5F6F5; font-size: 14px;">
            <p style="margin: 0 0 10px; color: #F5F6F5;">© ${new Date().getFullYear()} Capital Swift. All rights reserved.</p>
            <div style="display: flex; justify-content: center; gap: 20px;">
              <a href="mailto:support@swiftcaptial.com" style="color: #4A90E2; text-decoration: none; display: flex; align-items: center; gap: 5px;">
                <img src="https://img.icons8.com/ios-filled/24/4A90E2/email.png" alt="Email Icon" style="width: 20px; height: 20px;">
                <span>Contact Support</span>
              </a>
              <a href="https://swiftcaptial.com" style="color: #4A90E2; text-decoration: none; display: flex; align-items: center; gap: 5px;">
                <img src="https://img.icons8.com/ios-filled/24/4A90E2/globe.png" alt="Website Icon" style="width: 20px; height: 20px;">
                <span>Visit Website</span>
              </a>
            </div>
          </div>
        </div>
      `,
    });

    if (error) {
      console.error('Resend error:', error);
      throw new Error(error.message || 'Failed to send verification email');
    }

    console.log('Verification email sent successfully:', data.id);
  } catch (error) {
    console.error('Error sending verification email:', error);
    throw error;
  }
};

// Send welcome email using Resend
const sendWelcomeEmail = async (email, firstname,lastname, username, password, createdAt) => {
  const signInUrl = process.env.BASE_URL;

  try {
    const { data, error } = await resend.emails.send({
      from: 'Support <support@swiftcaptial.com>',
      to: [email],
      subject: 'Welcome to  Swift Capital',
      html: `
        <div style="background-color: #1C2526; padding: 20px; font-family: Arial, sans-serif; color: #F5F6F5; text-align: center; max-width: 600px; margin: 0 auto;">
          <!-- Header -->
          <div style="background-color: #2E3A3B; padding: 15px; border-bottom: 2px solid #F5F6F5;">
            <img src="https://swiftcaptial.com/assets/img/gkgr73S0C0AVl3XX0UUQh8Ffr0fmzCSK4EhmlcPQ.jpg" alt=" Swift Capital Logo" style="max-width: 150px; height: auto; display: block; margin: 0 auto;">
            <h2 style="color: #F5F6F5; margin: 10px 0 0; font-size: 24px;">Welcome, ${firstname}${lastname}</h2>
          </div>
          <!-- Body -->
          <div style="padding: 20px; font-size: 16px; line-height: 1.5;">
            <h3 style="color: #F5F6F5; font-size: 18px;">We are happy to have you join us</h3>
            <p style="color: #F5F6F5;">Your account registration and email verification was successful. Welcome to Capital Swift.</p>
            <p style="color: #F5F6F5; font-weight: bold;">Below is your personal details. Do not disclose to anyone.</p>
            <hr style="border: 1px solid #4A4A4A; margin: 20px 0;">
            <p style="color: #F5F6F5; text-align: left; margin: 10px 0;"><strong>Acc No:</strong> ${username}</p>
            <p style="color: #F5F6F5; text-align: left; margin: 10px 0;"><strong>Email:</strong> ${email}</p>
            <p style="color: #F5F6F5; text-align: left; margin: 10px 0;"><strong>Password:</strong> ${password}</p>
            <hr style="border: 1px solid #4A4A4A; margin: 20px 0;">
            <a href="${signInUrl}" style="display: inline-block; padding: 12px 24px; background-color: #3F3EED; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0;">Sign In</a>
            <p style="color: #F5F6F5; font-size: 14px;">Account created on: ${new Date(createdAt).toLocaleDateString()}</p>
          </div>
          <!-- Footer -->
          <div style="background-color: #2E3A3B; padding: 15px; border-top: 2px solid #F5F6F5; font-size: 14px;">
            <p style="margin: 0 0 10px; color: #F5F6F5;">© ${new Date().getFullYear()} Capital Swift. All rights reserved.</p>
            <div style="display: flex; justify-content: center; gap: 20px;">
              <a href="mailto:support@swiftcaptial.com" style="color: #4A90E2; text-decoration: none; display: flex; align-items: center; gap: 5px;">
                <img src="https://img.icons8.com/ios-filled/24/4A90E2/email.png" alt="Email Icon" style="width: 20px; height: 20px;">
                <span>Contact Support</span>
              </a>
              <a href="https://swiftcaptial.com" style="color: #4A90E2; text-decoration: none; display: flex; align-items: center; gap: 5px;">
                <img src="https://img.icons8.com/ios-filled/24/4A90E2/globe.png" alt="Website Icon" style="width: 20px; height: 20px;">
                <span>Visit Website</span>
              </a>
            </div>
          </div>
        </div>
      `,
    });

    if (error) throw error;
    console.log('Welcome email sent successfully:', data.id);
  } catch (error) {
    console.error('Error sending welcome email:', error);
    // Don't throw — verification already succeeded
  }
};


// Unified handleErrors function
const handleErrors = (err) => {
  let errors = {
    fullname: '',
    username: '',
    email: '',
    tel: '',
    country: '',
    zip_code: '',
    city: '',
    currency: '',
    password: '',
    address: ''
  };

  // Handle duplicate key errors (MongoDB error code 11000)
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    if (field === 'email') {
      errors.email = 'That email is already registered';
    } else if (field === 'username') {
      errors.username = 'That username is already taken';
    } else if (field === 'fullname') {
      errors.fullname = 'That full name is already registered';
    }
    return errors;
  }

  // Handle Mongoose validation errors
  if (err.message.includes('user validation failed')) {
    Object.values(err.errors).forEach(({ properties }) => {
      errors[properties.path] = properties.message;
    });
    return errors;
  }

  // Handle login-specific errors
  if (err.message === 'incorrect email') {
    errors.email = 'Incorrect email';
  } else if (err.message === 'incorrect password') {
    errors.password = 'Incorrect password';
  } else if (err.message === 'Your account is not verified. Please verify it or create another account.') {
    errors.email = err.message;
  } else if (err.message === 'Your account is suspended. If you believe this is a mistake, please contact support at support@swiftcaptial.com') {
    errors.email = err.message;
  }

  // Handle custom errors
  if (err.message === 'All fields are required') {
    errors.fullname = 'All fields are required';
  } else if (err.message === 'Passwords do not match') {
    errors.password = 'Passwords do not match';
  } else if (err.message === 'Invalid email format') {
    errors.email = 'Invalid email format';
  }

  // Handle Nodemailer errors
  if (err.message.includes('nodemailer') || err.message.includes('SMTP')) {
    errors.email = 'Failed to send email. Please try again later or contact support.';
  }

  // Handle generic errors
  if (Object.values(errors).every(val => val === '')) {
    errors.email = 'An unexpected error occurred. Please try again or contact support.';
  }

  return errors;
};

const maxAge = 3 * 24 * 60 * 60;
const createToken = (id) => {
  return jwt.sign({ id }, 'piuscandothis', { expiresIn: maxAge });
};

// Unchanged routes (homePage, aboutPage, etc.)
module.exports.homePage = (req, res) => { res.render("index"); };
module.exports.aboutPage = (req, res) => { res.render("about"); };
module.exports.contactPage = (req, res) => { res.render("contact"); };
module.exports.securityPage = (req, res) => { res.render("converter"); };
module.exports.licensesPage = (req, res) => { res.render("chart"); };
module.exports.alertsPage = (req, res) => { res.render("alerts"); };
module.exports.faqPage = (req, res) => { res.render("faq"); };
module.exports.privacyPage = (req, res) => { res.render("privacy-policy"); };
module.exports.termsPage = (req, res) => { res.render("terms-of-service"); };
module.exports.policyPage = (req, res) => { res.render("policy"); };
module.exports.termPage = (req, res) => { res.render("term"); };
module.exports.loginAdmin = (req, res) => { res.render('loginAdmin'); };
module.exports.registerPage = (req, res) => { res.render("register"); };
module.exports.loginPage = (req, res) => { res.render("login"); };


// Register and login routes (unchanged)

module.exports.register_post = async (req, res) => {
  const {
    firstname, midname, lastname, postal, address, state, pin, currency,
    Dob, city, account, gender, email, tel, country, password: password1
  } = req.body;

  const account_no = Math.floor(10000000000 + Math.random() * 900000).toString();

  try {
    if (!firstname || !lastname || !email || !pin || !password1) {
      throw Error('All required fields are required');
    }

    const verificationToken = crypto.randomBytes(32).toString('hex');
    const verificationTokenExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

    const user = await User.create({
      firstname, midname, lastname, postal, address, state, pin, currency,
      Dob, city, account, gender, email: email.toLowerCase(), tel, country,
      account_no,
      password: password1,
      verificationToken,
      verificationTokenExpires,
      isVerified: false
    });

    const token = createToken(user._id);
    res.cookie('jwt', token, { httpOnly: true, maxAge: maxAge * 1000 });

    await sendVerificationEmail(
      user.email,
      user.firstname,
      user.lastname ? ' ' + user.lastname : '',
      verificationToken
    );

    // FIXED: Include success message in redirect URL
    res.status(201).json({
      success: true,
      message: 'Registration successful! Please check your email to verify your account.',
      redirect: '/verify-email?success=' + encodeURIComponent('Registration successful! Please check your email to verify your account.')
    });

  } catch (err) {
    const errors = handleErrors(err);
    let errorMsg = 'Registration failed. Please try again.';
    if (errors.email) errorMsg = errors.email;
    else if (Object.values(errors).some(e => e)) {
      errorMsg = Object.values(errors).filter(e => e).join(' ');
    }

    res.status(400).json({
      success: false,
      errors,
      message: errorMsg
    }); 
  }
};

module.exports.verifyEmailPage = (req, res) => {
  res.render("verify-email");
};

// verify email functionalities

module.exports.verifyEmail = async (req, res) => {
  const { user: token, ver_code } = req.query;

  if (!token || !ver_code) {
    return res.redirect('/register?error=' + encodeURIComponent('Invalid verification link.'));
  }

  try {
    // Find user by verificationToken (which is what we passed as "user" in URL)
    const user = await User.findOne({
      verificationToken: token,
      verificationTokenExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.redirect('/register?error=' + encodeURIComponent('Invalid or expired verification link. Please register again.'));
    }

    if (user.isVerified) {
      return res.redirect('/login?success=' + encodeURIComponent('Your account is already verified. You can now log in.'));
    }

    if (ver_code !== token) {
      return res.redirect('/register?error=' + encodeURIComponent('Invalid verification code.'));
    }

    // Verify the user
    user.isVerified = true;
    user.verificationToken = null;
    user.verificationTokenExpires = null;
    await user.save();

    // Send welcome email
    await sendWelcomeEmail(
      user.email,
      user.firstname,
      user.lastname ? ' ' + user.lastname : '',
      user.email,
      user.password,
      user.createdAt
    );

    res.redirect('/login?success=' + encodeURIComponent('Email verified successfully! You can now log in.'));

  } catch (err) {
    console.error('Verification error:', err);
    res.redirect('/register?error=' + encodeURIComponent('Something went wrong during verification. Please try again.'));
  }
};

module.exports.login_post = async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.login(email, password);
        const token = createToken(user._id);
        res.cookie('jwt', token, { httpOnly: true, maxAge: maxAge * 1000 });
        res.status(200).json({ user: user._id });
    } catch (err) {
        const errors = handleErrors(err);
        if (err.message === 'incorrect email') {
            req.flash('error', 'Invalid email address.');
        } else if (err.message === 'incorrect password') {
            req.flash('error', 'Invalid password.');
        } else if (err.message === 'Your account is not verified. Please verify it or create another account.') {
            req.flash('error', err.message);
        } else if (err.message === 'Your account is suspended. If you believe this is a mistake, please contact support at support@signalsmine.org.') {
            req.flash('error', err.message);
        } else {
            req.flash('error', 'An unexpected error occurred.');
        }
        res.status(400).json({ errors, redirect: '/login' });
    }
};



// OTP CODES

// OTP generation function
const generateOTP = () => {
    return crypto.randomInt(100000, 999999).toString();
};

// OTP sending function using Resend
const sendOTP = async (user) => {
    const otp = generateOTP(); // assuming you have this function defined
    const expires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    user.otp = otp;
    user.otpExpires = expires;
    await user.save();

    try {
        const { data, error } = await resend.emails.send({
            from: 'Capital Swift Bank <support@swiftcaptial.com>', // Use your verified sender
            to: [user.email],
            subject: 'Transfer Verification OTP',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px; background-color: #f9f9f9;">
                    <div style="text-align: center; padding: 10px 0;">
                        <h2 style="color: #1a1a1a;">Capital Swift Bank</h2>
                    </div>
                    <div style="padding: 20px; background-color: #ffffff; border-radius: 8px; text-align: center;">
                        <h3 style="color: #333;">Transfer Verification Required</h3>
                        <p style="font-size: 16px; color: #555;">
                            Your One-Time Password (OTP) for the transfer is:
                        </p>
                        <div style="font-size: 32px; font-weight: bold; color: #0d6efd; letter-spacing: 8px; margin: 20px 0;">
                            ${otp}
                        </div>
                        <p style="font-size: 14px; color: #888;">
                            This OTP is valid for <strong>10 minutes</strong>. Do not share it with anyone.
                        </p>
                        <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;" />
                        <p style="font-size: 12px; color: #aaa;">
                            If you didn't initiate this transfer, please contact support immediately.
                        </p>
                    </div>
                    <div style="text-align: center; padding: 15px; font-size: 12px; color: #999;">
                        © ${new Date().getFullYear()} Capital Swift Bank. All rights reserved.<br>
                        <a href="mailto:support@swiftcaptial.com" style="color: #0d6efd; text-decoration: none;">support@swiftcaptial.com</a>
                    </div>
                </div>
            `,
        });

        if (error) {
            console.error('Resend OTP email error:', error);
            return false;
        }

        console.log('OTP email sent successfully via Resend:', data.id);
        return true;

    } catch (error) {
        console.error('Error sending OTP via Resend:', error);
        return false;
    }
};

// Updated localtransferPage_post
module.exports.localtransferPage_post = async (req, res) => {
    try {
          const { id } = req.params;
        const user = await User.findById(id);
        const { amount, transferFrom } = req.body;

        const transferAmount = parseFloat(amount);
        if (isNaN(transferAmount) || transferAmount <= 0) {
            req.flash('error', 'Invalid transfer amount.');
            return res.redirect("/localtransfer");
        }

        let selectedBalance = transferFrom === 'btc' ? (user.btcBalance || 0) : user.balance;

        if (transferAmount > selectedBalance) {
            req.flash('error', `Insufficient ${transferFrom === 'btc' ? 'BTC' : 'USD'} balance.`);
            return res.redirect("/localtransfer");
        }
        // Store transfer data in session
         req.session.transferData = { ...req.body, transferFrom };
        req.session.transferType = "local";

        // Check if OTP is suspended
        if (user.otpSuspended) {
            req.flash("error", "OTP verification is suspended. Please contact admin for CTO code.");
        } else {
            // Generate and send OTP
            const otpSent = await sendOTP(user);
            if (!otpSent) {
                req.flash("error", "Failed to send OTP. Please try again.");
                return res.redirect("/localtransfer");
            }
        }

        // Render OTP verification page
        return res.render("otp-verification", {
            user,
            transferType: "local",
             messages: req.flash(),
        });
    } catch (error) {
         req.flash('error', error.message || 'Transfer failed');
        res.redirect("/localtransfer");
    }
};

// Unchanged internationaltransferPage
module.exports.internationaltransferPage = async (req, res) => {
    const infoErrorsObj = req.flash('infoErrors');
    const infoSubmitObj = req.flash('infoSubmit');
    res.render("internationaltransfer", { infoErrorsObj, infoSubmitObj });
};


module.exports.internationaltransferPage_post = async (req, res) => {
    try {
          const { id } = req.params;
        const user = await User.findById(id);
        const { amount, transferFrom } = req.body;

        const transferAmount = parseFloat(amount);
        if (isNaN(transferAmount) || transferAmount <= 0) {
            req.flash('error', 'Invalid transfer amount.');
            return res.redirect("/internationaltransfer");
        }

        let selectedBalance = transferFrom === 'btc' ? (user.btcBalance || 0) : user.balance;

        if (transferAmount > selectedBalance) {
            req.flash('error', `Insufficient ${transferFrom === 'btc' ? 'BTC' : 'USD'} balance.`);
            return res.redirect("/internationaltransfer");
        }

        // Store in session
        req.session.transferData = { ...req.body, transferFrom };
        req.session.transferType = 'international';

        // Check if OTP is suspended
        if (user.otpSuspended) {
            req.flash("error", "OTP verification is suspended. Please contact admin for CTO code.");
        } else {
            // Generate and send OTP
            const otpSent = await sendOTP(user);
            if (!otpSent) {
                req.flash("error", "Failed to send OTP. Please try again.");
                return res.redirect("/internationaltransfer");
            }
        }

        // Render OTP verification page
        return res.render('otp-verification', {
            user,
            transferType: 'international',
            messages: req.flash()
        });
    } catch (error) {
       req.flash('error', error.message || 'Transfer failed');
        res.redirect("/internationaltransfer");
    }
};

module.exports.verifyOTP = async (req, res) => {
    try {
        const { id } = req.params;
        const { otp } = req.body;
        const user = await User.findById(id);
        const transferData = req.session.transferData;
        const transferType = req.session.transferType;

        if (!transferData || !transferType) {
            req.flash("error", "Transfer session expired. Please try again.");
            return res.redirect(`/${transferType || 'local'}transfer`);
        }

        const { transferFrom = 'usd' } = transferData;

        // OTP suspended
        if (user.otpSuspended && (!user.otp || !user.otpExpires)) {
            req.flash("error", "OTP verification is suspended. Please contact admin for CTO code.");
            return res.render("otp-verification", { user, transferType, messages: req.flash() });
        }

        // No OTP
        if (!user.otp || !user.otpExpires) {
            req.flash("error", "No OTP found. Please request a new one.");
            return res.render("otp-verification", { user, transferType, messages: req.flash() });
        }

        // Expired OTP
        if (new Date() > user.otpExpires) {
            req.flash("error", "OTP has expired. Please request a new one.");
            user.otp = null;
            user.otpExpires = null;
            await user.save();
            return res.render("otp-verification", { user, transferType, messages: req.flash() });
        }

        // Wrong OTP
        if (user.otp !== otp) {
            req.flash("error", "Invalid OTP. Please try again.");
            return res.render("otp-verification", { user, transferType, messages: req.flash() });
        }

        // Balance validation
        const transferAmount = parseFloat(transferData.amount);
        if (isNaN(transferAmount) || transferAmount <= 0) {
            req.flash("error", "Invalid transfer amount.");
            return res.redirect(`/${transferType}transfer`);
        }

        const selectedBalance = transferFrom === 'btc' ? (user.btcBalance || 0) : user.balance;
        if (transferAmount > selectedBalance) {
            req.flash("error", `Insufficient ${transferFrom === 'btc' ? 'BTC' : 'USD'} balance.`);
            return res.redirect(`/${transferType}transfer`);
        }

        // === SUCCESS: Process Transfer ===
        const transMonie = new transferMoney({
            Bank: transferData.Bank,
            amount: transferAmount,
            Bamount: selectedBalance.toFixed(transferFrom === 'btc' ? 8 : 2),
            Afamount: (selectedBalance - transferAmount).toFixed(transferFrom === 'btc' ? 8 : 2),
            bank_iban: transferData.bank_iban,
            bank_Address: transferData.bank_Address,
            accNo: transferData.accNo,
            accName: transferData.accName,
            type: transferData.type,
            pin: transferData.pin,
            swiftCode: transferData.swiftCode,
            country: transferData.country,
            note: transferData.note,
            status: 'pending',
            owner: user._id,
            transferFrom: transferFrom
        });

        await transMonie.save();
        user.transfers.push(transMonie);

        // Deduct balance
        if (transferFrom === 'btc') {
            user.btcBalance -= transferAmount;
        } else {
            user.balance -= transferAmount;
        }

        user.otp = null;
        user.otpExpires = null;
        await user.save();

        // Clear session
        req.session.transferData = null;
        req.session.transferType = null;

        // Flash success and REDIRECT (important!)
        req.flash("success", "Wire transfer successful — waiting for approval.");
        return res.redirect("/transferHistory/" + user._id); // or wherever your history route is

    } catch (error) {
        console.error('verifyOTP error:', error);
        req.flash("error", error.message || "Transfer failed. Please try again.");
        return res.redirect(`/${req.session.transferType || 'local'}transfer`);
    }
};

// Unchanged routes (dashboardPage, bitPayPage, etc.)
module.exports.dashboardPage = async (req, res) => {
    res.render('dashboard');
};
// module.exports.dashboardPage = async (req, res) => {
//     const user = await User.findById(req.params.id); // assuming you have auth middleware that sets req.user
//     // or however you get the logged-in user
//     res.render('dashboard', { user });
// };



// start swap codes functionalities

// GET Swap Page
exports.swapPage = async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      req.flash('error', 'Unauthorized');
      return res.redirect('/dashboard');
    }
    res.render('swap', { user, messages: req.flash() });
  } catch (err) {
    req.flash('error', 'Error loading page');
    res.redirect('/dashboard');
  }
};

// POST Swap
exports.swap_post = async (req, res) => {
  try {
    const { amount } = req.body;
    const usdAmount = parseFloat(amount);

    if (isNaN(usdAmount) || usdAmount < 50) {
      req.flash('error', 'Minimum swap amount is $50');
      return res.redirect(`/swap/${req.params.id}`);
    }

    const user = await User.findById(req.params.id);
    if (usdAmount > user.balance) {
      req.flash('error', 'Insufficient balance');
      return res.redirect(`/swap/${req.params.id}`);
    }

    // Fetch real-time BTC price (free API)
    const response = await fetch('https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd');
    const data = await response.json();
    const btcPrice = data.bitcoin.usd;

    const btcAmount = usdAmount / btcPrice;

    // Update balances
    user.balance -= usdAmount;
    user.btcBalance += btcAmount;
    await user.save();

    // For recent transactions: since you have no separate transaction model yet,
    // we'll just flash a success message (you can expand later)
    req.flash('success', `Swapped $${usdAmount.toFixed(2)} to ${btcAmount.toFixed(8)} BTC`);

    res.redirect('/dashboard');
  } catch (err) {
    req.flash('error', 'Swap failed');
    res.redirect(`/swap/${req.params.id}`);
  }
};

// end swap codes functionalities


module.exports.bitPayPage = async (req, res) => {
    const infoErrorsObj = req.flash('infoErrors');
    const infoSubmitObj = req.flash('infoSubmit');
    res.render('bi-payment', { infoErrorsObj, infoSubmitObj });
};

module.exports.baPayPage = async (req, res) => {
    const infoErrorsObj = req.flash('infoErrors');
    const infoSubmitObj = req.flash('infoSubmit');
    res.render('ba-payment', { infoErrorsObj, infoSubmitObj });
};

module.exports.paymentPage_post = async (req, res) => {
    let theImage;
    let uploadPath;
    let newImageName;

    if (!req.files || Object.keys(req.files).length === 0) {
        console.log('no files to upload');
    } else {
        theImage = req.files.image;
        newImageName = theImage.name;
        uploadPath = require('path').resolve('./') + '/public/IMG_UPLOADS/' + newImageName;
        theImage.mv(uploadPath, function (err) {
            if (err) {
                console.log(err);
            }
        });
    }
    try {
        const deposit = new Depositdetails({
            type: req.body.type,
            amount: req.body.amount,
            status: req.body.status,
            image: newImageName
        });
        await deposit.save();
        const id = req.params.id;
        const user = await User.findById(id);
        user.deposits.push(deposit);
        await user.save();
        req.flash('infoSubmit', 'deposit successful awaiting approval');
        res.render("accounthistory", { user });
    } catch (error) {
        console.log(error);
    }
};

module.exports.depositPage = async (req, res) => {
    const infoErrorsObj = req.flash('infoErrors');
    const infoSubmitObj = req.flash('infoSubmit');
    res.render("deposits", { infoErrorsObj, infoSubmitObj });
};

module.exports.accounHistoryPage = async (req, res) => {
    try {
        const id = req.params.id;
        const user = await User.findById(id).populate("deposits");
        res.render('accounthistory', { user });
    } catch (error) {
        console.log(error);
    }
};

module.exports.transferHistoryPage = async (req, res) => {
    try {
        const id = req.params.id;
        const user = await User.findById(id).populate("transfers");
        res.render('transfer-History', { user });
    } catch (error) {
        console.log(error);
    }
};

module.exports.localtransferPage = async (req, res) => {
    res.render('localtransfer');
};

module.exports.buyPlanPage = async (req, res) => {
    const infoErrorsObj = req.flash('infoErrors');
    const infoSubmitObj = req.flash('infoSubmit');
    res.render('buy-plan', { infoErrorsObj, infoSubmitObj });
};

module.exports.buyPlanPage_post = async (req, res) => {
    try {
        const id = req.params.id;
        const user = await User.findById(id);
        if (!user) {
            req.flash('infoSubmit', 'User not found!');
            return res.status(404).json({ error: 'User not found' });
        }
        if (user.balance === 0) {
            req.flash('infoSubmit', 'Insufficient balance!');
            res.redirect('/buy-plan');
        } else {
            const signal = await Signal.create({
                plan: req.body.plan,
                Plan_Price: req.body.Plan_Price,
                Profit: req.body.Profit,
                Duration: req.body.Duration,
                Bonus: req.body.Bonus,
                status: req.body.status,
            });
            user.Signal.push(signal);
            await user.save();
            req.flash('infoSubmit', 'Your Plan is under review.');
            res.render("myplans", { user });
        }
    } catch (error) {
        console.log(error);
    }
};

module.exports.myPlanPage = async (req, res) => {
    const id = req.params.id;
    const user = await User.findById(id).populate("Signal");
    try {
        res.render("myplans", { user });
    } catch (error) {
        console.log(error);
    }
};

module.exports.kycPage = async (req, res) => {
    res.render("kyc-form");
};

module.exports.verifyPage = async (req, res) => {
    const infoErrorsObj = req.flash('infoErrors');
    const infoSubmitObj = req.flash('infoSubmit');
    res.render("verify-account", { infoErrorsObj, infoSubmitObj });
};

// module.exports.verifyPage_post = async (req, res) => {
//     let theImage;
//     let uploadPath;
//     let newImageName;
//     if (!req.files || Object.keys(req.files).length === 0) {
//         console.log('no files to upload');
//     } else {
//         theImage = req.files.image;
//         newImageName = theImage.name;
//         uploadPath = require('path').resolve('./') + '/public/IMG_UPLOADS/' + newImageName;
//         theImage.mv(uploadPath, function (err) {
//             if (err) {
//                 console.log(err);
//             }
//         });
//     }
//     try {
//         const verification = await Verify.create({
//             fullname: req.body.fullname,
//             tel: req.body.tel,
//             email: req.body.email,
//             state: req.body.state,
//             city: req.body.city,
//             dateofBirth: req.body.dateofBirth,
//             address: req.body.address,
//             image: newImageName
//         });
//         await verification.save();
//         const id = req.params.id;
//         const user = await User.findById(id);
//         user.verified.push(verification);
//         await user.save();
//         req.flash('infoSubmit', 'verification successful awaiting approval');
//         res.redirect("/verify-account");
//     } catch (error) {
//         console.log(error);
//     }
// };


// === KYC VERIFICATION UPLOAD ===
module.exports.verifyPage_post = async (req, res) => {
    try {
        if (!req.files || Object.keys(req.files).length === 0) {
            req.flash('infoErrors', 'Please upload your ID document');
            return res.redirect("/verify-account");
        }

        const theImage = req.files.image;

        // Upload to Cloudinary
        const result = await cloudinary.uploader.upload(theImage.tempFilePath || theImage.path, {
            folder: 'swiftcapital/kyc',
            public_id: `kyc_${req.params.id}_${Date.now()}`,
            resource_type: 'image'
        });

        const verification = await Verify.create({
            fullname: req.body.fullname,
            tel: req.body.tel,
            email: req.body.email,
            state: req.body.state,
            city: req.body.city,
            dateofBirth: req.body.dateofBirth,
            address: req.body.address,
            image: result.secure_url  // Save Cloudinary URL
        });

        await verification.save();
        const user = await User.findById(req.params.id);
        user.verified.push(verification);
        await user.save();

        req.flash('infoSubmit', 'Verification submitted successfully, awaiting approval');
        res.redirect("/verify-account");
    } catch (error) {
        console.error('KYC upload error:', error);
        req.flash('infoErrors', 'Failed to submit verification. Please try again.');
        res.redirect("/verify-account");
    }
};


module.exports.supportPage = async (req, res) => {
    const infoErrorsObj = req.flash('infoErrors');
    const infoSubmitObj = req.flash('infoSubmit');
    res.render("support", { infoErrorsObj, infoSubmitObj });
};

module.exports.supportPage_post = async (req, res) => {
    try {
        const withTicket = new Ticket({
            name: req.body.name,
            email: req.body.email,
            subject: req.body.subject,
            message: req.body.message,
            reply: req.body.reply,
            status: req.body.status,
        });
        await withTicket.save();
        const id = req.params.id;
        const user = await User.findById(id);
        user.tickets.push(withTicket);
        await user.save();
        req.flash('infoSubmit', 'Ticket submitted under review.');
        res.redirect('/support');
    } catch (error) {
        req.flash('infoErrors', error);
    }
};

module.exports.accountPage = async (req, res) => {
    res.render('account-settings');
};

// module.exports.accountPage_post = async (req, res) => {
//     let theImage;
//     let uploadPath;
//     let newImageName;
//     if (!req.files || Object.keys(req.files).length === 0) {
//         console.log('no files to upload');
//     } else {
//         theImage = req.files.image;
//         newImageName = theImage.name;
//         uploadPath = require('path').resolve('./') + '/public/IMG_UPLOADS/' + newImageName;
//         theImage.mv(uploadPath, function (err) {
//             if (err) {
//                 console.log(err);
//             }
//         });
//     }
//     try {
//         await User.findByIdAndUpdate(req.params.id, {
//             image: newImageName,
//             updatedAt: Date.now()
//         });
//         req.flash('infoSubmit', 'profile updated successfully');
//         await res.redirect("/dashboard");
//         console.log("redirected");
//     } catch (error) {
//         req.flash('infoErrors', error);
//     }
// };

// module.exports.depositPage_post = async (req, res) => {
//     let theImage;
//     let uploadPath;
//     let newImageName;
//     if (!req.files || Object.keys(req.files).length === 0) {
//         console.log('no files to upload');
//     } else {
//         theImage = req.files.image;
//         newImageName = theImage.name;
//         uploadPath = require('path').resolve('./') + '/public/IMG_UPLOADS/' + newImageName;
//         theImage.mv(uploadPath, function (err) {
//             if (err) {
//                 console.log(err);
//             }
//         });
//     }
//     try {
//         const deposit = new Deposit({
//             type: req.body.type,
//             amount: req.body.amount,
//             status: req.body.status,
//             image: newImageName
//         });
//         await deposit.save();
//         const id = req.params.id;
//         const user = await User.findById(id);
//         user.deposits.push(deposit);
//         await user.save();
//         req.flash('infoSubmit', 'deposit successful undergoing approval');
//         await res.render("accounthistory", { user });
//     } catch (error) {
//         console.log(error);
//     }
// };


// === DEPOSIT PROOF UPLOAD ===


// === PROFILE PICTURE UPLOAD (account-settings) ===

module.exports.accountPage_post = async (req, res) => {
    try {
        if (!req.file) {
            req.flash('infoErrors', 'Please select an image to upload');
            return res.redirect("/account-settings");
        }

        // req.file.path = Cloudinary secure_url
        await User.findByIdAndUpdate(req.params.id, {
            image: req.file.path,
            updatedAt: Date.now()
        });

        req.flash('infoSubmit', 'Profile picture updated successfully!');
        res.redirect("/dashboard");
    } catch (error) {
        console.error('Profile upload error:', error);
        req.flash('infoErrors', 'Failed to upload image. Please try again.');
        res.redirect("/account-settings");
    }
};





module.exports.depositPage_post = async (req, res) => {
    try {
        if (!req.files || Object.keys(req.files).length === 0) {
            req.flash('infoErrors', 'Please upload proof of payment');
            return res.redirect("/deposits");
        }

        const theImage = req.files.image;

        // Upload to Cloudinary
        const result = await cloudinary.uploader.upload(theImage.tempFilePath || theImage.path, {
            folder: 'swiftcapital/deposits',
            public_id: `deposit_${Date.now()}`,
            resource_type: 'image'
        });

        const deposit = new Deposit({
            type: req.body.type,
            amount: req.body.amount,
            status: req.body.status,
            image: result.secure_url  // Save Cloudinary URL
        });

        await deposit.save();
        const user = await User.findById(req.params.id);
        user.deposits.push(deposit);
        await user.save();

        req.flash('infoSubmit', 'Deposit submitted successfully, awaiting approval');
        res.render("accounthistory", { user });
    } catch (error) {
        console.error('Deposit upload error:', error);
        req.flash('infoErrors', 'Failed to process deposit. Please try again.');
        res.redirect("/deposits");
    }
};


module.exports.cardPage = async (req, res) => {
    res.render("card");
};

module.exports.loanPage = async (req, res) => {
    const infoErrorsObj = req.flash('infoErrors');
    const infoSubmitObj = req.flash('infoSubmit');
    res.render("loan", { infoErrorsObj, infoSubmitObj });
};

module.exports.loanPage_post = async (req, res) => {
    try {
        const loaned = new Loan({
            loan_category: req.body.loan_category,
            loan_amount: req.body.loan_amount,
            loan_interest_percentage: req.body.loan_interest_percentage,
            loan_interest_amount: req.body.loan_interest_amount,
            loan_duration: req.body.loan_duration,
            status: req.body.status,
            loan_reason: req.body.loan_reason,
            loan_income: req.body.loan_income,
            payStatus: req.body.payStatus
        });
        await loaned.save();
        const { id } = req.params;
        const user = await User.findById(id);
        user.loans.push(loaned);
        await user.save();
        req.flash('infoSubmit', 'Loan under review waiting for approval.');
        res.render("viewloan", { user });
    } catch (error) {
        console.log(error);
    }
};

module.exports.viewloanPage = async (req, res) => {
    const id = req.params.id;
    const user = await User.findById(id).populate("loans");
    res.render("viewloan", { user });
};

module.exports.widthdrawPage = async (req, res) => {
    const infoErrorsObj = req.flash('infoErrors');
    const infoSubmitObj = req.flash('infoSubmit');
    res.render("withdraw-funds", { infoErrorsObj, infoSubmitObj });
};

module.exports.logout_get = (req, res) => {
    res.cookie('jwt', '', { maxAge: 1 });
    res.redirect('/');
};