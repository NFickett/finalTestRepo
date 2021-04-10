const mongoose = require('mongoose');
const {isEmail} = require('validator');
const bcrypt = require('bcrypt')

//defines a basic user
const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: [true,'Please enter an Email'],
        unique: true,
        lowercase: true,
        validate: [isEmail,'Please enter a valid email']
    },
    password: {
        type: String,
        required: [true, 'Please enter a password'],
        minlength: [6, 'Password must be 6 characters']
    },
})


//fire a function to hash the password before a doc is saved to db
userSchema.pre('save', async function(next){
    const salt = await bcrypt.genSalt();
    this.password = await bcrypt.hash(this.password, salt);
    next();
})

//static method to login user
userSchema.statics.login = async function (email,password){
    const user = await this.findOne({ email });  //finds email
    if(user) {  //if email exists
        const auth = await bcrypt.compare(password, user.password) //check if password is correct
        if (auth){ //if it is, return the user
            return user;
        }
        throw Error('incorrect password') //wrong password
    }
    throw Error('incorrect email') // nonexistant email
}

const User = mongoose.model('user', userSchema);

module.exports = User;