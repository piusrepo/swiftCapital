const express = require("express");

const router = express.Router();

const { homePage, registerPage, loginPage, register_post, login_post, loginAdmin, logout_get, helpPage, forexPage, cryptoPage, stocksPage, optionsPage, copyPage, securityPage, termsPage, licensesPage, aboutPage, alertsPage, faqPage, privacyPage, contactPage } = require("../controllers/userController");
const { loginAdmin_post } = require("../controllers/adminController");

router.get("/", homePage);
router.get("/about-us", aboutPage);
router.get("/contact-us", contactPage);
router.get("/converter", securityPage);
router.get("/terms-of-service", termsPage);
router.get("/chart", licensesPage);
router.get("/alerts", alertsPage);

router.get("/faq", faqPage);
router.get("/privacy-policy", privacyPage);

router.get("/register", registerPage);
router.post('/register',register_post);

router.get("/login", loginPage);
router.post('/login',login_post)

router.get('/loginAdminse', loginAdmin);
router.post('/loginAdminse', loginAdmin_post)

router.get('/logout', logout_get)









module.exports = router;
