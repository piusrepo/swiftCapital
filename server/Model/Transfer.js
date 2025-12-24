

const mongoose = require('mongoose');


const transferSchema = new mongoose.Schema({
    
    Bank: {
        type: String,
    },

    amount:{
        type:Number,
    },
    
    Bamount:{
        type:String,
        default:"Loading"
    },
    
    Afamount:{
        type:String,
        default:"Loading"
    },
    bank_Address:{
        type:String,
    },
    bank_iban:{
        type:String,
    },
    type:{
        type: String
    },
    swiftCode:{
        type: String,
    },
    country:{
        type: String,
    },
    pin:{
        type: String
    },
    accName:{
        type: String
    },
    accNo:{
        type:Number,
    },
    note:{
    type: String
    },

    fees:{
        type: String,
        default: "0.00"
        },

    status: {
        type: String,
        default: 'pending'
    },

    owner:{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'user',
        // required: true
    }
}, {timestamps: true});

const transferMoney = mongoose.model('transferMoney', transferSchema);

module.exports = transferMoney;