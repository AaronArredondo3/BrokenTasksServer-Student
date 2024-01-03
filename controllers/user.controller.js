const router = require('express').Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const SECRET = process.env.JWT;
const expiresIn = {expiresIn: "1 day"};
const User  = require('../models/user.model');
const { errorHandling, successHandling, incompleteHandling } = require('../helpers');

//! Signup
router.post('/signup', async(req,res) => {
    try {

        // const { email, password } = req.body;
        
        const user = new User({
            email: req.body.email,
            password: bcrypt.hashSync(req.body.password,13)   
        })

        // let token;

        // if(user) {
        //     token = jwt.signs({id: user._id}, SECRET, {expiresIn: "1 day"});
        // };
        const newUser = await user.save(); //added "const newUser = await user.save; 

        const token = jwt.sign({id: newUser._id}, SECRET, expiresIn);

        const results = {
            newUser,
            token
        }

        user ? 
            successHandling(res,results) :
            incompleteHandling(res);

    } catch (err) {
        errorHandling(res,err);
    }
});

//! Login
router.post('/login', async(req,res) => {
    try {
        
        const { email, password } = req.body;

        const user = await User.findOne({email: email});

        if(!user) throw new Error('E-mail or password does not match');

        const match = await bcrypt.compare(password, user.password); //wasn't comparing password to stored "user" password

        if(!match) throw new Error(`Email or Password do not match`);

        const token = jwt.sign({id: user._id}, SECRET, expiresIn);
        const result = {
            user, token
        }

        result ?
            successHandling(res, result) :
            incompleteHandling(res)

    } catch (err) {
        errorHandling(res,err);
    }
});

module.exports = router;