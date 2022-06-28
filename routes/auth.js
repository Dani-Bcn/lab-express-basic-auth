var express = require('express');
var router = express.Router();
const User = require("../models/User.model")
const isLoggedIn = require("../middlewares")
const bcrypt = (require("bcrypt"))
const saltRounds =10
router.get("/signup" ,(req,res,next)=>{
    res.render("auth/signup")
})
router.get("/login" ,(req,res,next)=>{
    res.render("auth/login")
})
router.post("/signup" , async(req,res,next)=>{
    const {username, password} =req.body
     if(!username || !password){
         res.render("auth/signup", {error: 'Fields cannot be empty'})
         return
     }
     const regex =/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).{8,}$/
     if(!regex.test(password)){
           res.render("auth/signup", {error: 'The password field must have uppercase, lowercase, numbers and a special character'})         
           return
     }
    try{
        const salt = await bcrypt.genSalt(saltRounds) 
        const codeHash = await bcrypt.hash(password, salt) 
        const user = await User.create({username, codeHash})
        res.redirect("/")
    }   
    catch(err){

        res.render("auth/signup",{err})
    }
})

router.post("/login" , async(req,res,next)=>{
    const {username, password} =req.body
     if(!username || !password){
         res.render("auth/login", {error: 'Fields cannot be empty'})
         return
     }    
    try{
        const user = await User.findOne({username:username})       
 
        if(!user){
            res.render("auth/login", {error: "Data not found"})
            return
        }else{
          
            const passCompare =  bcrypt.compare(password, user.codeHash)
            console.log(password)
            console.log(user.codeHash)
            console.log(passCompare)
            if(passCompare){
                 req.session.currentUser = user
                 res.render("index",{user})
            }else{
                res.render("auth/login", {error: "Data not found"})
                return
            }            
        }       
    }   
    catch{
        res.render("auth/login")
    }
})
router.post("/logout" ,(req, res,next)=>{
    req.session.destroy((err)=>{
        if(err){
            next(err)
        }else{
            res.redirect("/")
        }
    })
})
module.exports = router;
router.get("/main" , isLoggedIn ,(req, res, next)=>{
    res.render("main")
})
router.get("/private" , isLoggedIn ,(req, res, next)=>{
    res.render("private")
})