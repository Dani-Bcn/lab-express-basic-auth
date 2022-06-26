var express = require('express');
var router = express.Router();
const User = require("../models/User.model")
const isLoggedIn = require("../middlewares")
const bcrypt = (require("bcrypt"))
const saltRounds =10
// muestra el formulario para registrarse
router.get("/signup" ,(req,res,next)=>{
    res.render("auth/signup")
})
// muestra el formulario para iniciar sesión
router.get("/login" ,(req,res,next)=>{
    res.render("auth/login")
})
// envio de registro del usuario
router.post("/signup" , async(req,res,next)=>{
    const {username, password} =req.body
    // si los campos user o pasword están vacios
     if(!username || !password){
         res.render("auth/signup", {error: 'Fields cannot be empty'})
         return
     }
     //requisitos password carácteres
     const regex =/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).{8,}$/
     //si password cumple las condiciones de regex... test() devuelve true o false 
     if(!regex.test(password)){
           res.render("auth/signup", {error: 'The password field must have uppercase, lowercase, numbers and a special character'})         
           return
     }
    try{
        const salt = await bcrypt.genSalt(saltRounds) // veces que lo queremos heashear
        const codeHash = await bcrypt.hash(password, salt) //encriptamos el password con el metodo hash tantas veces
        const user = await User.create({username, codeHash})// Creamos el usuario encriptado
        res.redirect("/")
    }   
    catch{
        res.render("auth/signup")
    }
})
// envio formulario para iniciar sesión
router.post("/login" , async(req,res,next)=>{
    const {username, password} =req.body
     if(!username || !password){
         res.render("auth/login", {error: 'Fields cannot be empty'})
         return
     }    
    try{
        const user = await User.findOne({username:username})       
        //si el usuario no se encuentra en la db
        if(!user){
            res.render("auth/login", {error: "Data not found"})
            return
        }else{
            //comparamos el campo de password introducido, con el password hasheado de la base de datos => (user.codeHash)           
            const passCompare =  bcrypt.compare(password, user.codeHash)//devuleve true o false
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
    // con session.destroy => destruimos la cookie
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