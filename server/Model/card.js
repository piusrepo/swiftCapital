
const mongoose = require("mongoose");

const cardSchema = new mongoose.Schema({
    cardNo:{
    type: String,
    default: "xxxxxxxxxxxx"
    },
    card_cvv:{
        type: String,
        default: "xxxx"
    },
    cardName:{
        type: String,
        default: "xxxxxxxxxxxxxx"
    },
    card_exp:{
        type: String,
        default: "xxxxxxxxxx"
    },
    card_type:{
        type: String,
        default: "xxxxxxx"
    },

    status:{
        type:String,
        default: "not active"
    },
},{timestamps:true})

const Card = mongoose.model("card",cardSchema)

module.exports = Card;

