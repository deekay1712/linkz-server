const router = require('express').Router();
const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const otpGenerator = require('otp-generator');
const nodemailer = require('nodemailer');
const multer = require('multer');

const generateOtp = () => {
    return otpGenerator.generate(6, { upperCase: false, specialChars: false });
};

const generateAccessToken = (user) => {
    return jwt.sign({ id: user.id }, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: '15m'
    });
};
const generateRefreshToken = (user) => {
    return jwt.sign({ id: user.id }, process.env.REFRESH_TOKEN_SECRET, {
    });
};

const sendMail = async(email, otp) => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'OTP for login',
        text: `Your OTP is ${otp}`
    };
    await transporter.sendMail(mailOptions);
}

//Verify function for JWT
const verify = async(req, res, next) => {
    const authHeader = req.headers['authorization'];
    if(authHeader) {
        const token = authHeader.split(' ')[1];

        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
            if(err) {
                return res.status(403).send({ message: 'Invalid token' });
            }
            req.user = user;
            next();
        });
    }
    else {
        return res.status(401).send({ message: 'You are not authenticated!' });
    }
};

//Refresh token
router.post('/refresh', (req,res)=>{
    //take the refresh token from the user
    const refreshToken = req.cookies.refreshToken;
    //Send error if no refresh token is provided
    if(!refreshToken) {
        return res.status(401).send({ message: 'You are not authenticated' });
    }
    //Check if the refresh token is valid
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if(err) {
            return res.status(403).send({ message: 'Invalid token' });
        }
        const newAccessToken = generateAccessToken(user);
        const newRefreshToken = generateRefreshToken(user);
        res.cookie('refreshToken', newRefreshToken, { httpOnly: true, sameSite: true });
        res.status(200).send({ accessToken: newAccessToken});
    })
});

//SignUp a new user
router.post('/signup', async(req, res) => {
    const { username, email, password } = req.body;
    const user = new User({
        username,
        email
    });
    try {
        const isExist = await User.findOne({ email });
        if(isExist) {
            return res.status(409).send({ message: 'Email already exists' });
        }
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        user.otp = generateOtp();
        sendMail(email, user.otp);
        await user.save();
        res.status(200).send({ message: 'User created successfully', userId: user._id });
    } catch (err) {
        res.status(400).send(err);
    }
});

// Login a user
router.post('/login', async(req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).send({ message: 'Invalid email' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).send({ message: 'Invalid password' });
        }
        if(!user.isAuthenticated){
            return res.status(400).send({ message: 'Verify again', userId: user._id });
        }
        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);

        res.cookie('refreshToken', refreshToken, { httpOnly: true, maxAge: 1000 * 60 * 60 * 24 * 365 });
        res.send({accessToken, user});
    } catch (err) {
        res.status(400).send(err);
    }
});

//Get user details
router.get('/', verify, async(req, res) => {
    try {
        const user = await User.findById(req.user.id);
        res.send({user});
    } catch (err) {
        res.status(400).send(err);
    }
});

//Delete a user
router.delete('/:userId', verify, async(req, res) => {
    if(req.user.id === req.params.userId) {
        try {
            await User.findByIdAndDelete(req.params.userId);
            res.send({ message: 'User deleted successfully' });
        } catch (err) {
            res.status(400).send(err);
        }
    }
    else {
        res.status(403).send({ message: 'You are not authorized to delete this user' });
    }
});

//LogOut a user
router.post('/logout', verify, (req, res) => {
    console.log("logout");
    res.clearCookie('refreshToken');
    res.status(200).send({ message: 'Logged out successfully' });
});

//Verify a user using OTP
router.post('/verify/:userId', async(req, res) => {
    const { otp } = req.body;
    try {
        const user = await User.findById(req.params.userId);
        if(user.otp === otp) {
            user.isAuthenticated= true;
            await user.save();
            res.send({ message: 'User verified successfully' });
        }
        else {
            res.status(400).send({ message: 'Invalid OTP' });
        }
    }
    catch (err) {
        res.status(400).send(err);
    }
});

// Resend an OTP
router.post('/resend-otp/:userId', async(req, res) => {
    try {
        const user = await User.findById(req.params.userId);
        user.otp = generateOtp();
        sendMail(user.email, user.otp);
        await user.save();
        res.send({ message: 'OTP sent successfully' });
    }
    catch (err) {
        res.status(400).send(err);
    }
});

//Reset a user's password
router.post('/reset', async(req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if(!user) {
            return res.status(400).send({ message: 'Invalid email' });
        }
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        user.isAuthenticated = false;
        await user.save();
        res.send({ message: 'Password reset successfully' });
    }
    catch (err) {
        res.status(400).send(err);
    }
});

//Update a user's image
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'images/');
    }, 
    filename: (req, file, cb) => {
        cb(null, req.params.userId + '.jpg');
    }
});

const upload = multer({ storage: storage });

router.post('/upload/:userId', upload.single('image'), async(req, res) => {
    try {
        const user = await User.findById(req.params.userId);
        user.profilePicture = req.params.userId + '.jpg';
        await user.save();
        res.send({ message: 'Image updated successfully', user });
    }
    catch (err) {
        res.status(400).send(err);
    }
});

module.exports = router;