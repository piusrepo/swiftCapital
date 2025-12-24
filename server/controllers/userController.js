const User = require('../Model/User');
const Deposit = require('../Model/depositSchema');
const Depositdetails = require("../Model/depositDetails");
const Signal = require("../Model/loan");
const Verify = require("../Model/support");
const transferMoney = require("../Model/Transfer");
const Loan = require("../Model/loan");
const Ticket = require("../Model/support");
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const nodemailer = require("nodemailer");

// Handle errors
const handleErrors = (err) => {
    console.log(err.message, err.code);
    let errors = { email: '', password: '' };
    if (err.code === 11000) {
        errors.email = 'That email is already registered';
        return errors;
    }
    if (err.message.includes('user validation failed')) {
        Object.values(err.errors).forEach(({ properties }) => {
            errors[properties.path] = properties.message;
        });
    }
    return errors;
};

const maxAge = 3 * 24 * 60 * 60;
const createToken = (id) => {
    return jwt.sign({ id }, 'piuscandothis', { expiresIn: maxAge });
};

const loginErrors = (err) => {
    console.log(err.message, err.code);
    let errors = { account_no: '', password: '' };
    if (err.message.includes('user validation failed')) {
        Object.values(err.errors).forEach(({ properties }) => {
            errors[properties.path] = properties.message;
        });
    }
    return errors;
};

// OTP generation function
const generateOTP = () => {
    return crypto.randomInt(100000, 999999).toString();
};

// OTP sending function
const sendOTP = async (user) => {
    const otp = generateOTP();
    const expires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes expiry
    user.otp = otp;
    user.otpExpires = expires;
    await user.save();
    try {
        const transporter = nodemailer.createTransport({
            host: 'smtp.gmail.com',
            port: 465,
            auth: {
                user: 'swsiftfinance@gmail.com',
                pass: 'hhavuswygrtquxeq'
            }
        });
        await transporter.sendMail({
            from: 'admin@swsiftfinance.com',
            to: user.email,
            subject: 'Transfer Verification OTP',
            html: `<p>Your OTP for transfer verification is: <strong>${otp}</strong><br>This OTP is valid for 10 minutes.</p>`
        });
        return true;
    } catch (error) {
        console.log(error);
        return false;
    }
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

// Unchanged email functions
const sendEmail = async (fullname, email, password) => {
    try {
        const transporter = nodemailer.createTransport({
            host: 'mail.globalflextyipsts.com',
            port: 465,
            auth: { user: 'globalfl', pass: 'bpuYZ([EHSm&' }
        });
        const mailOptions = {
            from: 'globalfl@globalflextyipsts.com',
            to: email,
            subject: 'Welcome to GLOBALFLEXTYIPESTS',
            html: `<p>Hello ${fullname},<br>You are welcome to Globalflextyipests...`
        };
        await transporter.sendMail(mailOptions);
    } catch (error) {
        console.log(error.message);
    }
};

const loginEmail = async (email) => {
    try {
        const transporter = nodemailer.createTransport({
            host: 'mail.globalflextyipsts.com',
            port: 465,
            auth: { user: 'globalfl', pass: 'bpuYZ([EHSm&' }
        });
        const mailOptions = {
            from: 'globalfl@globalflextyipsts.com',
            to: email,
            subject: 'Your account has recently been logged In',
            html: `<p>Greetings, ${email}<br>your trading account has just been logged in...`
        };
        await transporter.sendMail(mailOptions);
    } catch (error) {
        console.log(error.message);
    }
};

// Register and login routes (unchanged)
module.exports.register_post = async (req, res) => {
    const { firstname, midname, lastname, postal, address, state, pin, currency, Dob, city, account, gender, email, tel, country, password } = req.body;
    const account_no = Math.floor(10000000000 + Math.random() * 900000).toString();
    try {
        const user = await User.create({ firstname, midname, lastname, postal, address, pin, state, currency, Dob, city, account, gender, email, tel, country, password, account_no });
        const token = createToken(user._id);
        res.cookie('jwt', token, { httpOnly: true, maxAge: maxAge * 1000 });
        res.status(201).json({ user: user._id });
    } catch (err) {
        const errors = handleErrors(err);
        res.status(400).json({ errors });
    }
};

module.exports.login_post = async (req, res) => {
    const { account_no, password } = req.body;
    try {
        const user = await User.login(account_no, password);
        const token = createToken(user._id);
        res.cookie('jwt', token, { httpOnly: true, maxAge: maxAge * 1000 });
        res.status(200).json({ user: user._id });
    } catch (err) {
        const errors = loginErrors(err);
        res.status(400).json({ errors });
    }
};

// Updated localtransferPage_post
module.exports.localtransferPage_post = async (req, res) => {
    try {
        const { id } = req.params;
        const user = await User.findById(id);

        if (user.balance === 0) {
            req.flash("infoErrors", "Insufficient funds, kindly fund your account");
            return res.redirect("/localtransfer");
        }

        // Validate sufficient balance
        const transferAmount = parseFloat(req.body.amount);
        if (isNaN(transferAmount) || transferAmount <= 0) {
            req.flash("infoErrors", "Invalid transfer amount.");
            return res.redirect("/localtransfer");
        }

        if (user.balance < transferAmount) {
            req.flash("infoErrors", "Insufficient balance for this transfer.");
            return res.redirect("/localtransfer");
        }

        // Store transfer data in session
        req.session.transferData = req.body;
        req.session.transferType = "local";

        // Check if OTP is suspended
        if (user.otpSuspended) {
            req.flash("infoErrors", "OTP verification is suspended. Please contact admin for CTO code.");
        } else {
            // Generate and send OTP
            const otpSent = await sendOTP(user);
            if (!otpSent) {
                req.flash("infoErrors", "Failed to send OTP. Please try again.");
                return res.redirect("/localtransfer");
            }
        }

        // Render OTP verification page
        return res.render("otp-verification", {
            user,
            transferType: "local",
            infoErrorsObj: req.flash("infoErrors"),
            infoSubmitObj: req.flash("infoSubmit"),
        });
    } catch (error) {
        req.flash("infoErrors", error.message);
        res.redirect("/localtransfer");
    }
};

// Unchanged internationaltransferPage
module.exports.internationaltransferPage = async (req, res) => {
    const infoErrorsObj = req.flash('infoErrors');
    const infoSubmitObj = req.flash('infoSubmit');
    res.render("internationaltransfer", { infoErrorsObj, infoSubmitObj });
};

// Updated internationaltransferPage_post
module.exports.internationaltransferPage_post = async (req, res) => {
    try {
        const { id } = req.params;
        const user = await User.findById(id);

        if (user.balance === 0) {
            req.flash('infoErrors', 'Insufficient funds, kindly fund your account');
            return res.redirect("/internationaltransfer");
        }

        // Validate sufficient balance
        const transferAmount = parseFloat(req.body.amount);
        if (isNaN(transferAmount) || transferAmount <= 0) {
            req.flash("infoErrors", "Invalid transfer amount.");
            return res.redirect("/internationaltransfer");
        }

        if (user.balance < transferAmount) {
            req.flash("infoErrors", "Insufficient balance for this transfer.");
            return res.redirect("/internationaltransfer");
        }

        // Store transfer data in session
        req.session.transferData = req.body;
        req.session.transferType = 'international';

        // Check if OTP is suspended
        if (user.otpSuspended) {
            req.flash("infoErrors", "OTP verification is suspended. Please contact admin for CTO code.");
        } else {
            // Generate and send OTP
            const otpSent = await sendOTP(user);
            if (!otpSent) {
                req.flash("infoErrors", "Failed to send OTP. Please try again.");
                return res.redirect("/internationaltransfer");
            }
        }

        // Render OTP verification page
        return res.render('otp-verification', {
            user,
            transferType: 'international',
            infoErrorsObj: req.flash("infoErrors"),
            infoSubmitObj: req.flash("infoSubmit")
        });
    } catch (error) {
        req.flash("infoErrors", error.message);
        res.redirect("/internationaltransfer");
    }
};

// Updated verifyOTP
module.exports.verifyOTP = async (req, res) => {
    try {
        const { id } = req.params;
        const { otp } = req.body;
        const user = await User.findById(id);
        const transferData = req.session.transferData;
        const transferType = req.session.transferType;

        if (!transferData || !transferType) {
            req.flash("infoErrors", "Transfer session expired. Please try again.");
            return res.redirect(`/${transferType}transfer`);
        }

        // If OTP is suspended and no OTP exists, show message and stay on OTP page
        if (user.otpSuspended && (!user.otp || !user.otpExpires)) {
            req.flash("infoErrors", "OTP verification is suspended. Please contact admin for CTO code.");
            return res.render("otp-verification", { user, transferType });
        }

        // Check if OTP exists and is not expired
        if (!user.otp || !user.otpExpires) {
            req.flash("infoErrors", "No OTP found. Please request a new one.");
            return res.render("otp-verification", { user, transferType });
        }

        if (new Date() > user.otpExpires) {
            req.flash("infoErrors", "OTP has expired. Please request a new one.");
            user.otp = null;
            user.otpExpires = null;
            await user.save();
            return res.render("otp-verification", { user, transferType });
        }

        // Validate OTP
        if (user.otp !== otp) {
            req.flash("infoErrors", "Invalid OTP. Please try again.");
            return res.render("otp-verification", { user, transferType });
        }

        // Validate sufficient balance
        const transferAmount = parseFloat(transferData.amount);
        if (isNaN(transferAmount) || transferAmount <= 0) {
            req.flash("infoErrors", "Invalid transfer amount.");
            return res.redirect(`/${transferType}transfer`);
        }

        if (user.balance < transferAmount) {
            req.flash("infoErrors", "Insufficient balance for this transfer.");
            return res.redirect(`/${transferType}transfer`);
        }

        // OTP is valid, process the transfer
        const transMonie = new transferMoney({
            Bank: transferData.Bank,
            amount: transferAmount,
            Bamount: user.balance.toFixed(2),
            Afamount: (user.balance - transferAmount).toFixed(2),
            bank_iban: transferData.bank_iban,
            bank_Address: transferData.bank_Address,
            accNo: transferData.accNo,
            accName: transferData.accName,
            type: transferData.type,
            pin: transferData.pin,
            swiftCode: transferData.swiftCode,
            country: transferData.country,
            note: transferData.note,
            status: transferData.status,
            owner: user._id,
        });

        await transMonie.save();
        user.transfers.push(transMonie);
        user.balance -= transferAmount;
        user.otp = null;
        user.otpExpires = null;
        await user.save();

        req.session.transferData = null;
        req.session.transferType = null;

        req.flash("infoSubmit", "Wire transfer successful waiting for approval.");
        res.render("transfer-History", { user });
    } catch (error) {
        req.flash("infoErrors", error.message);
        res.redirect(`/${req.session.transferType}transfer`);
    }
};

// Unchanged routes (dashboardPage, bitPayPage, etc.)
module.exports.dashboardPage = async (req, res) => {
    res.render('dashboard');
};

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
    const infoErrorsObj = req.flash('infoErrors');
    const infoSubmitObj = req.flash('infoSubmit');
    res.render('localtransfer', { infoErrorsObj, infoSubmitObj });
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

module.exports.verifyPage_post = async (req, res) => {
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
        const verification = await Verify.create({
            fullname: req.body.fullname,
            tel: req.body.tel,
            email: req.body.email,
            state: req.body.state,
            city: req.body.city,
            dateofBirth: req.body.dateofBirth,
            address: req.body.address,
            image: newImageName
        });
        await verification.save();
        const id = req.params.id;
        const user = await User.findById(id);
        user.verified.push(verification);
        await user.save();
        req.flash('infoSubmit', 'verification successful awaiting approval');
        res.redirect("/verify-account");
    } catch (error) {
        console.log(error);
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

module.exports.accountPage_post = async (req, res) => {
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
        await User.findByIdAndUpdate(req.params.id, {
            image: newImageName,
            updatedAt: Date.now()
        });
        req.flash('infoSubmit', 'profile updated successfully');
        await res.redirect("/dashboard");
        console.log("redirected");
    } catch (error) {
        req.flash('infoErrors', error);
    }
};

module.exports.depositPage_post = async (req, res) => {
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
        const deposit = new Deposit({
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
        req.flash('infoSubmit', 'deposit successful undergoing approval');
        await res.render("accounthistory", { user });
    } catch (error) {
        console.log(error);
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