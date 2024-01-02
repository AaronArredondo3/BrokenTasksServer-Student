const jwt = require('jsonwebtoken');
const User = require('../models/user.model')


const validateSession = async (req,res,next) => {
    try {
        
        const token = req.headers.authorization;
        const decoded = await jwt.verify(token, process.env.JWT);

        const user = await User.findById(decoded.id);
        if(!user) throw new Error(`User not found`);

        req.user;

        return next();

    } catch (err) {
        res.json({message: err.message})
    }
}

module.exports = validateSession;