
const express = require('express');

const router = express.Router();

const adminController = require('../controllers/adminController');

//************************************* */  Admin Dashboard  routes**********************//

router.get('/adminRoute',adminController.adminPage );


router.get('/viewUser/:id',adminController.viewUser );

router.get('/editUser/:id',adminController.editUser );

router.put('/editUser/:id', adminController.editUser_post);

// In adminRoute.js
router.get('/suspendOTP/:id', adminController.suspendOTP);
router.get('/unsuspendOTP/:id', adminController.unsuspendOTP);

// //************************************* */ All Deposits  routes**********************//

router.get('/allFunding',adminController.allDeposit );

router.get('/viewDeposit/:id',adminController.viewDeposit );

router.get('/editDeposit/:id',adminController.editDeposit);

router.put('/editDeposit/:id',adminController.editDeposit_post );

// //************************************* */ All Account Upgrades routes**********************//
router.get("/allLoans", adminController.allupgradesPage)
router.get("/viewUpgrade/:id", adminController.viewUprgadesPage)
router.get("/editUpgrade/:id", adminController.editUpgradesPage);
router.put('/editUpgrade/:id',adminController.editUpgrade_post );

router.get("/allTransfer", adminController.allTransfer)
router.get("/viewTransfer/:id", adminController.viewTransfer)
router.get("/editTransfer/:id", adminController.editTransferPage)
router.put("/editTransfer/:id", adminController.editTransfer_post)


// //************************************* */ All Tickets**********************//
router.get("/allTickets", adminController.allTTicketPage)
router.get("/viewTickets/:id", adminController.viewTicketPage)


// //************************************* */ All Delete routes**********************//
router.delete('/deleteUser/:id', adminController.deletePage);
router.delete('/deleteDeposit/:id', adminController.deleteDeposit);
router.delete("/deleteTickets/:id", adminController.deleteTicket)
router.delete("/deleteUpgrade/:id", adminController.deleteUpgrade)
router.delete("/deleteTransfer/:id", adminController.deleteTransfer)



module.exports = router;
