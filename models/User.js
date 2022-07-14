const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        // unique: true,
        minlength: 3,
        maxlength: 20
    },
    email: {
        type: String,
        required: true,
        unique: true,
        minlength: 3,
    },
    password: {
        type: String,
        required: true,
        minlength: 6
    },
    profilePicture: {
        type: String,
        default: ""
    },
    isAuthenticated: {
        type: Boolean,
        default: false
    },
    otp: {
        type: String,
        default: ""
    }
}, { timestamps: true });

module.exports = mongoose.model('User', UserSchema);