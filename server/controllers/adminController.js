

const jwt = require('jsonwebtoken')
const Deposit = require("../Model/depositSchema");
const User = require("../Model/User");
const Ticket = require("../Model/support");
const transferMoney = require("../Model/Transfer");
const Loan = require("../Model/loan");
const nodemailer = require('nodemailer');


const handleErrors = (err) => {
  console.log(err.message, err.code);
  let errors = { email: '', password: '', };

  // duplicate email error
  if (err.code === 11000) {
    errors.email = 'that email is already registered';
    return errors;
  }
  // validation errors
  if (err.message.includes('user validation failed')) {
    // console.log(err);
    Object.values(err.errors).forEach(({ properties }) => {
      // console.log(val);
      // console.log(properties);
      errors[properties.path] = properties.message;
    });
  }


  return errors;
}


const maxAge = 3 * 24 * 60 * 60;
const createToken = (id) => {
  return jwt.sign({ id }, 'piuscandothis', {
    expiresIn: maxAge
  });
};


module.exports.loginAdmin_post = async(req, res) =>{
  try {
    const { email, password } = req.body;

    const user = await User.findOne({email: email});

    if(user){
    const passwordMatch = await (password, user.password);

    if (passwordMatch) {
      
      if(!user.role == "admin"){
        res.render('login', handleErrors('Email and password is incorrect') )
      }else{
        const token = createToken(user._id);
        res.cookie('jwt', token, { httpOnly: true, maxAge: maxAge * 1000 });
        res.status(200).json({ user: user._id });
      }
      
    } else {
      res.render('login', handleErrors() )
    }
    } else{
      res.render('login',handleErrors() )
    }
    
  } catch (error) {
    console.log(error)
  }
    
}



// *******************ADMIN DASHBOARD CONTROLLERS *************************//


module.exports.adminPage = async(req, res) =>{
        let perPage = 100;
        let page = req.query.page || 1;
    
        try {
          const user = await User.aggregate([ { $sort: { createdAt: -1 } } ])
            .skip(perPage * page - perPage)
            .limit(perPage)
            .exec(); 
          // const count = await User.count();
    
          res.render('adminDashboard',{user});
    
        } catch (error) {
          console.log(error);
        } 
    } 


module.exports.viewUser = async(req, res) =>{
    try {
        const user = await User.findOne({ _id: req.params.id })
        res.render("viewUser",{
          user
        })
    
      } catch (error) {
        console.log(error);
      }
    
    }
  


    module.exports.editUser = async(req, res) =>{
      try {
          const user = await User.findOne({ _id: req.params.id })
      
          res.render('editUser', {
            user
          })
      
        } catch (error) {
          console.log(error);
        }
  }




module.exports.editUser_post = async(req, res) =>{
    try {
        await User.findByIdAndUpdate(req.params.id,{
          firstname: req.body.firstname,
          midname: req.body.midname,
          lastname: req.body.lastname,
          tel: req.body.tel,
          email: req.body.email,
          limit: req.body.limit,
          ref_no: req.body.ref_no,
          postal: req.body.postal,
          address: req.body.address,
          state: req.body.state,
          currency: req.body.currency,
          account_no: req.body.account_no,
          Dob: req.body.Dob,
          account: req.body.account,
          password: req.body.password,
          balance: req.body.balance,
          gender: req.body.gender,
          bank_name:req.body.bank_name,
          account_name:req.body.account_name,
          fees:req.body.fees,
          sortcode:req.body.sortcode,
          deacc_no:req.body.deacc_no,
          deacc_bank:req.body.deacc_bank,
          deacc_swift:req.body.deacc_swift,
          deacc_name:req.body.deacc_name,
          pending:req.body.pending,
          de_wallet:req.body.de_wallet,
          cardBal:req.body.cardBal,
          cardNumb:req.body.cardNumb,
          card_cvv:req.body.card_cvv,
          card_exp:req.body.card_exp,
          card_status:req.body.card_status,
          card_type:req.body.card_type,
          total_deposit:req.body.total_deposit,
          updatedAt: Date.now()
        });

      
          //  if(User){
          // sendEmail(req.body.fullname,req.body.email, req.body.available, req.body.balance, req.body.bonus,req.body.widthdrawBalance, req.body.profit, req.body.totalDeposit,req.body.totalWidthdraw,req.body.signal, req.body.verifiedStatus,req.body.account, req.body.session )
          // }else{
          //   console.log(error);
          // }
        await res.redirect(`/editUser/${req.params.id}`);
        console.log('redirected');
      } catch (error) {
        console.log(error);
      }
    
}


// In adminController.js
module.exports.suspendOTP = async(req, res) => {
    try {
        const user = await User.findById(req.params.id);
        user.otpSuspended = true;
        await user.save();
        req.flash('infoSubmit', 'OTP verification suspended for user');
        res.redirect(`/editUser/${req.params.id}`);
    } catch (error) {
        console.log(error);
        req.flash('infoErrors', 'Failed to suspend OTP verification');
        res.redirect(`/editUser/${req.params.id}`);
    }
};

module.exports.unsuspendOTP = async(req, res) => {
    try {
        const user = await User.findById(req.params.id);
        user.otpSuspended = false;
        await user.save();
        req.flash('infoSubmit', 'OTP verification enabled for user');
        res.redirect(`/editUser/${req.params.id}`);
    } catch (error) {
        console.log(error);
        req.flash('infoErrors', 'Failed to enable OTP verification');
        res.redirect(`/editUser/${req.params.id}`);
    }
};

module.exports.deletePage = async(req, res) =>{
  try {
    await User.deleteOne({ _id: req.params.id });
      res.redirect("/adminiRoute")
    } catch (error) {
      console.log(error);
    }
}

// *******************ALL DEPOSITS CONTROLLERS *************************//

module.exports.allDeposit = async(req, res) =>{
    let perPage = 100;
    let page = req.query.page || 1;

    try {
      const deposit = await Deposit.aggregate([ { $sort: { createdAt: -1 } } ])
        .skip(perPage * page - perPage)
        .limit(perPage)
        .exec(); 
     

      res.render('allFunding',{
        deposit
      });

    } catch (error) {
      console.log(error);
    } 
}

module.exports.viewDeposit = async(req, res) =>{
    try {
        const deposit = await Deposit.findOne({ _id: req.params.id })
    
        res.render('viewDeposits',{
          deposit
        })
    
      } catch (error) {
        console.log(error);
      }

}

module.exports.editDeposit = async(req, res) =>{
    try {
        const deposit = await Deposit.findOne({ _id: req.params.id })
    
        res.render('editDeposit',{
          deposit
        })
    
      } catch (error) {
        console.log(error);
      }
  
}

module.exports.editDeposit_post  = async(req, res) =>{
    try {
        await Deposit.findByIdAndUpdate(req.params.id,{
          type: req.body.type,
          amount: req.body.amount,
          status: req.body.status,
          narration: req.body.narration,
          updatedAt: Date.now()
        });
        await res.redirect(`/editDeposit/${req.params.id}`);
        
        console.log('redirected');
      } catch (error) {
        console.log(error);
      }
    
}

module.exports.deleteDeposit = async(req, res) =>{
    try {
        await Deposit.deleteOne({ _id: req.params.id });
        res.redirect("/adminiRoute")
      
    } catch (error) {
        console.log(error)
    }
    
}

// // *******************ACCOUNT UPGRADES CONTROLLERS *************************//

module.exports.allupgradesPage = async(req, res)=>{
  let perPage = 100;
  let page = req.query.page || 1;

  try {
    const upgrade = await Loan.aggregate([ { $sort: { createdAt: -1 } } ])
      .skip(perPage * page - perPage)
      .limit(perPage)
      .exec(); 
    // const count = await Widthdraw.count();

    res.render('allAccountsUpgrade',{
      upgrade
    });

  } catch (error) {
    console.log(error);
  } 
}


module.exports.viewUprgadesPage = async(req, res)=>{

  try {
    const upgrade = await Loan.findOne({ _id: req.params.id })

res.render('viewallAccountsUpgrade',{
  upgrade
})

      } catch (error) {
        console.log(error);
      }
}

module.exports.editUpgradesPage = async(req, res)=>{
  try {
    const upgrade = await Loan.findOne({ _id: req.params.id })

  res.render('editallAccountsUpgrade',{
  upgrade
  })
      } catch (error) {
        console.log(error);
      }
}

module.exports.editUpgrade_post  = async(req, res)=>{
  try {
    await Loan.findByIdAndUpdate(req.params.id,{
      loan_category:req.body.loan_category,
       loan_amount:req.body.loan_amount,
       loan_duration:req.body.loan_duration,
       loan_interest_amount:req.body.loan_interest_amount,
       loan_interest_percentage:req.body.loan_interest_percentage,
       loan_reason:req.body.loan_reason,
       loan_income:req.body.loan_income,
       payStatus: req.body.payStatus,
       status:req.body.status,
      updatedAt: Date.now()
    });
    await res.redirect(`/editUpgrade/${req.params.id}`);
    
    console.log('redirected');
  } catch (error) {
    console.log(error);
  }
}

module.exports.deleteUpgrade = async(req, res)=>{
  try {
    await Loan.deleteOne({ _id: req.params.id });
    res.redirect("/adminiRoute")
  
} catch (error) {
    console.log(error)
}
}


// ********************************TRANSFER*******************************************//

module.exports.allTransfer = async(req, res)=>{
  let perPage = 100;
  let page = req.query.page || 1;

  try {
    const transfer = await transferMoney.aggregate([ { $sort: { createdAt: -1 } } ])
      .skip(perPage * page - perPage)
      .limit(perPage)
      .exec(); 
    // const count = await Widthdraw.count();

    res.render('allTransfer',{transfer});

  } catch (error) {
    console.log(error);
  } 
}

module.exports.editTransferPage = async(req, res)=>{
  try {
    const transfer = await transferMoney.findOne({ _id: req.params.id })

  res.render('editTransfer',{
    transfer
  })
      } catch (error) {
        console.log(error);
      }
}

module.exports.editTransfer_post  = async(req, res)=>{
  try {
    await transferMoney.findByIdAndUpdate(req.params.id,{
      Bank: req.body.Bank,
      amount: req.body.amount,
      Bamount: req.body.Bamount,
      Afamount: req.body.Afamount,
      beneficiary: req.body.beneficiary,
      accNo: req.body.accNo,
      pin: req.body.pin,
      swiftCode: req.body.swiftCode,
      country: req.body.country,
      note: req.body.note,
      status: req.body.status,
      updatedAt: Date.now()
    });
    await res.redirect(`/editTransfer/${req.params.id}`);
    
    console.log('redirected');
  } catch (error) {
    console.log(error);
  }
}

module.exports.viewTransfer= async(req, res)=>{
  try {
    const transfer = await transferMoney.findOne({ _id: req.params.id })

res.render('viewTransfer',{transfer})
      } catch (error) {
        console.log(error);
      }
}

module.exports.deleteTransfer = async(req, res)=>{
  try {
    await transferMoney.deleteOne({ _id: req.params.id });
    res.redirect("/adminiRoute")
  
} catch (error) {
    console.log(error)
}
}

// *********************************TICKETS*********************************//
module.exports.allTTicketPage = async(req, res)=>{
  let perPage = 100;
  let page = req.query.page || 1;

  try {
    const tickets = await Ticket.aggregate([ { $sort: { createdAt: -1 } } ])
      .skip(perPage * page - perPage)
      .limit(perPage)
      .exec(); 
    // const count = await Widthdraw.count();

    res.render('allTickets',{ tickets});

  } catch (error) {
    console.log(error);
  }   
}


module.exports.viewTicketPage = async(req, res)=>{

  try {
    const tickets = await Ticket.findOne({ _id: req.params.id })

res.render('viewTickets',{tickets})

      } catch (error) {
        console.log(error);
      }
}


module.exports.deleteTicket = async(req, res)=>{
  try {
    await Ticket.deleteOne({ _id: req.params.id });
    res.redirect("/adminiRoute")
  
} catch (error) {
    console.log(error)
}
}