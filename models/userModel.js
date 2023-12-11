const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const validator = require('validator')



const Schema = mongoose.Schema

const userSchema = new Schema({
    email : {
        type : String,
        required : true,
        unique : true
    },
    password : {
        type : String,
        required : true,
    }
})


// static signup method
userSchema.statics.signup = async function (email, password) {
    
    //validation 
    if(!email || !password) {
        throw Error('both the feilds are necessary')
    }
    if(!validator.isEmail(email))
    {
        throw Error('not a valid email')
    }
    if((!validator.isStrongPassword(password)))
    {
        throw Error('please use a stronger password')
    }

    const exist = await this.findOne({email});

    if(exist){
        throw Error('email already in use')
    }

    const salt = await bcrypt.genSalt(5);

    const hash = await bcrypt.hash(password,salt);

    const user = await this.create({email, password: hash})
    return user;
}

//static login method

userSchema.statics.login = async function(email, password){
    if(!email || !password) {
        throw Error('both the feilds are necessary')
    }

    const user = await this.findOne({email});

    if(!user)
    {
        throw Error('email not registered please signup first ');
    }

    const match = await bcrypt.compare(password, user.password);

    if(!match)
    {
        throw Error('incorrect password')
    }

    return user;

}

module.exports = mongoose.model('User',userSchema)