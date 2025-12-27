const mongoose = require('mongoose');
const validator = require('validator');

const userSchema = new mongoose.Schema({
  isSuspended: {
    type: Boolean,
    default: false,
  },
  firstname: {
    type: String,
  },
  midname: {
    type: String,
  },
  lastname: {
    type: String,
  },
  tel: {
    type: String,
  },
  email: {
    type: String,
    unique: true,
    lowercase: true,
    required: [true, 'Please enter an email'], // Fixed validator syntax
  },
  limit: {
    type: String,
    default: "500,000,00"
  },
  country: {
    type: String
  },
  ref_no: {
    type: String,
    default: "1234567890"
  },
  postal: {
    type: String,
    default: "postal code"
  },
  address: {
    type: String,
    default: "your address"
  },
  state: {
    type: String,
    default: "your state"
  },
  currency: {
    type: String,
    default: "$"
  },
  Dob: {
    type: String,
  },
  city: {
    type: String,
    default: "your city"
  },
  account: {
    type: String,
  },
  password: {
    type: String,
    required: true, // Added required
  },
  image: {
    type: String,
  },
  balance: {
    type: Number,
    default: 0
  },
  btcBalance: {
  type: Number,
  default: 0
},
  total_deposit: {
    type: String,
    default: "0.00"
  },
  gender: {
    type: String,
  },
  bank_name: {
    type: String,
    default: "your bank name"
  },
  account_name: {
    type: String,
    default: "your account name"
  },
  fees: {
    type: String,
    default: "0.00"
  },
  account_no: {
    type: String,
    default: "your account number"
  },
  sortcode: {
    type: String,
    default: "388130"
  },
  deacc_no: {
    type: Number,
    default: "99388383"
  },
  deacc_bank: {
    type: String,
    default: "Mining Bank"
  },
  deacc_swift: {
    type: String,
    default: "3222ASD"
  },
  deacc_name: {
    type: String,
    default: "Miller lauren"
  },
  pending: {
    type: String,
    default: "0.00"
  },
  de_wallet: {
    type: String,
    default: "bc1qkspwvk9ge7rfl7374t96s95es64vc4fysk2nu5"
  },
  pin: {
    type: String,
    required: true, // Added required
  },
  cardBal: {
    type: String,
    default: "0.00"
  },
  cardNumb: {
    type: String,
    default: "xxxxxxxxxxxx"
  },
  card_cvv: {
    type: String,
    default: "xxxx"
  },
  card_exp: {
    type: String,
    default: "xxxxxxxxxxxxxx"
  },
  card_status: {
    type: String,
    default: "Not Active"
  },
  card_type: {
    type: String,
    default: "xxxxxxxxxxxx"
  },
  otp: {
    type: String, 
    default: null,
  },
  otpExpires: {
    type: Date,
    default: null,
  },
  isVerified: {
    type: Boolean,
    default: false,
  },
  verificationCode: {
    type: String,
    default: null,
  },
  kycVerified: {
    type: Boolean,
    default: false,
  },
  verifiedStatus: {
    type: String,
    default: 'not Verified!',
  },
  verificationToken: {
    type: String,
    default: null,
  },
  verificationTokenExpires: {
    type: Date,
    default: null,
  },
  Depositdetails: {
    type: [mongoose.Schema.Types.ObjectId],
    ref: 'details'
  },
  transfers: {
    type: [mongoose.Schema.Types.ObjectId],
    ref: 'transferMoney'
  },
  cards: {
    type: [mongoose.Schema.Types.ObjectId],
    ref: 'card'
  },
  loans: {
    type: [mongoose.Schema.Types.ObjectId],
    ref: 'loan'
  },
  tickets: {
    type: [mongoose.Schema.Types.ObjectId],
    ref: 'ticket'
  },
  deposits: {
    type: [mongoose.Schema.Types.ObjectId],
    ref: 'deposit'
  },
  otpSuspended: {
    type: Boolean,
    default: false
  },
  role: {
    type: Number,
    default: 0
  }
}, { timestamps: true });

// Login static method (unchanged - plain text comparison)
userSchema.statics.login = async function (email, password) {
  const user = await this.findOne({ email });
  if (!user) {
    throw Error('incorrect email');
  }

  if (user.isSuspended) {
    throw Error('Your account is suspended. If you believe this is a mistake, please contact support at support@swiftcaptial.com');
  }
  if (!user.isVerified) {
    throw Error('Your account is not verified. Please check your email and click the verification link, or create a new account.');
  }
  // Direct string comparison for passwords
  if (password !== user.password) {
    throw Error('incorrect password');
  }
  return user;
};

const User = mongoose.model('user', userSchema);

module.exports = User;