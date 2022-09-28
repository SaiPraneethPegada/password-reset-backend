var bcrypt = require("bcryptjs");
var jwt = require("jsonwebtoken");
require("dotenv").config();

const saltRounds = 12;
const { ACTIVATION_KEY, REFRESH_KEY, ACCESS_KEY } = process.env;

async function hashPassword(password) {
    var salt = await bcrypt.genSalt(saltRounds);
    var hashedPassword = await bcrypt.hash(password, salt);
    return hashedPassword;
}

async function hashCompare(password, hashedPassword) {
    return await bcrypt.compare(password, hashedPassword);
}

let createToken = {
    activation: (payload) => {
        return jwt.sign(payload, ACTIVATION_KEY, { expiresIn: "5m" });
    },

    refresh: (payload) => {
        return jwt.sign(payload, REFRESH_KEY, { expiresIn: "24h" });
    },

    access: (payload) => {
        return jwt.sign(payload, ACCESS_KEY, { expiresIn: "5m" });
    },
};

module.exports = { hashPassword, hashCompare, createToken };
