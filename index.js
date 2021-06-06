const express = require("express");
const mongodb = require("mongodb");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const uniqid = require("uniqid");
require("dotenv").config();
const app = express();
const port = process.env.PORT || 3100;
const mongoClient = mongodb.MongoClient;
app.use(express.json());
const dbURL = process.env.DB_URL;
const objectId = mongodb.ObjectID;
app.use(cors());
const URL="https://competent-poincare-02e6d8.netlify.app/";

app.get("/",(req,res)=>{
    res.status(200).send("Hello There! This page works");
});

app.post("/signup", async(req,res)=>{
    try{
        let client = await mongoClient.connect(dbURL);
        let db = client.db(process.env.DB_NAME);
        let check = await db.collection("users").findOne({email:req.body.email});
        if(check){
            res.status(400).send("User is already registered!");
        }
        else{
            let salt = await bcrypt.genSalt(10);
            let hash = await bcrypt.hash(req.body.password,salt);
            req.body.password = hash;
            let signup_token = await jwt.sign({email: req.body.email},process.env.SIGN_KEY);
            await db.collection("users").insertOne({firstname:req.body.firstname,lastname:req.body.lastname,email:req.body.email,password:req.body.password,active:0,sign_token:signup_token});
            let transporter = nodemailer.createTransport({
                host: "smtp.office365.com",
                service:"hotmail",
                port: 587,
                secure: false, // true for 465, false for other ports
                auth: {
                    user: process.env.USER, // generated ethereal user
                    pass: process.env.PASS, // generated ethereal password
                  },
              });
            let info = await transporter.sendMail({
                from: 'shwetha.iyer@hotmail.com', // sender address
                to: req.body.email, // list of receivers
                subject: "Account Activation link", // Subject line
                text: `Hello, Please click on the link to activate your account   ${URL+"activateaccount/"+signup_token}`, // plain text body 
              });
              console.log("Message sent: %s", info.messageId);
              console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));
            res.status(200).send("New user inserted and email sent");
        }
        client.close();
    }
    catch (error) {
        console.log(error);
        res.status(500).json({
            message: "Internal Server Error",
        });
    }
});

app.put("/activateaccount/:token", async(req,res)=>{
    try{
        let client = await mongoClient.connect(dbURL);
        let db = client.db(process.env.DB_NAME);
        let check = await db.collection("users").findOne({sign_token:req.params.token});
        if(check){
            await db.collection("users").updateOne({sign_token:req.params.token},{$unset:{sign_token:1},$set:{active:1}});
            res.status(200).send("Token exists, account activated");
        }
        else
        res.status(404).send("cant find token");
        client.close();
    }
    catch (error) {
        console.log(error);
        res.status(500).json({
            message: "Internal Server Error",
        });
    }
});


app.post("/login",async(req,res)=>{
    try{
        let client = await mongoClient.connect(dbURL);
        let db = client.db(process.env.DB_NAME);
        let check = await db.collection("users").findOne({email:req.body.email});
        if(check){
            if(check.active===1){
                let isValid = await bcrypt.compare(req.body.password,check.password);
                if(isValid){
                    res.status(200).json({
                        id:check._id
                    });
                }
                else{
                    res.status(401).send("Wrong password!");
                }
            }
            else{
                res.status(400).send("Account not activated");
            }
        }
        else{
            res.status(404).send("Email does not exist!");
        }
        client.close();
    }
    catch (error) {
        console.log(error);
        res.status(500).json({
            message: "Internal Server Error",
        });
    }
});

app.post("/forgot",async(req,res)=>{
    try{
        let client = await mongoClient.connect(dbURL);
        let db = client.db(process.env.DB_NAME);
        let check = await db.collection("users").findOne({email:req.body.email});
        if(check){
            let pwd_token = await jwt.sign({email: req.body.email},process.env.PASS_KEY);     
            await db.collection("users").updateOne({email:req.body.email},{$set:{pass_token:pwd_token}});
            let transporter = nodemailer.createTransport({
                host: "smtp.office365.com",
                service:"hotmail",
                port: 587,
                secure: false, // true for 465, false for other ports
                auth: {
                    user: process.env.USER, // generated ethereal user
                    pass: process.env.PASS, // generated ethereal password
                  },
              });
            let info = await transporter.sendMail({
                from: 'shwetha.iyer@hotmail.com', // sender address
                to: req.body.email, // list of receivers
                subject: "Password Reset link", // Subject line
                text: `Hello, Please click on the link to reset your password   ${URL+"resetpwd/"+pwd_token}`, // plain text body 
              });
              console.log("Message sent: %s", info.messageId);
              console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));
            
            res.status(200).send("Password reset email sent");
        }
        else{
            res.status(404).send("Email does not exist!");
        }
        client.close();
    }
    catch (error) {
        console.log(error);
        res.status(500).json({
            message: "Internal Server Error",
        });
    }
});

app.get("/resetpwdcheck/:token", async(req,res)=>{
    try{
        let client = await mongoClient.connect(dbURL);
        let db = client.db(process.env.DB_NAME);
        let check = await db.collection("users").findOne({pass_token:req.params.token});
        if(check)
        res.status(200).send("exists");
        else
        res.status(404).send("cant find token");
        client.close();
    }
    catch (error) {
        console.log(error);
        res.status(500).json({
            message: "Internal Server Error",
        });
    }
});

app.put("/resetpwd/:token", async(req,res)=>{
    try{
        let client = await mongoClient.connect(dbURL);
        let db = client.db(process.env.DB_NAME);
        let salt = await bcrypt.genSalt(10);
        let hash = await bcrypt.hash(req.body.password,salt);
        req.body.password = hash;
        await db.collection("users").updateOne({pass_token:req.params.token},{$set:{password:req.body.password},$unset:{pass_token:1}});
        res.status(200).send("password is reset");
        client.close();
    }
    catch (error) {
        console.log(error);
        res.status(500).json({
            message: "Internal Server Error",
        });
    }
});

app.get("/dashboard/:id",async(req,res)=>{
    try{
        let client = await mongoClient.connect(dbURL);
        let db = client.db(process.env.DB_NAME);
        let data = await db.collection("users").findOne({_id:objectId(req.params.id)},{fields:{password:0}});
        if(data){
            res.status(200).json(data);
        }
        else{
            res.status(404).send("Not found");
        }
        client.close();
    }
    catch (error) {
        console.log(error);
        res.status(500).json({
            message: "Internal Server Error",
        });
    }
});

app.post("/urlshorten/:id",async(req,res)=>{
    try{
        let client = await mongoClient.connect(dbURL);
        let db = client.db(process.env.DB_NAME);
        let data = await db.collection("users").findOne({_id:objectId(req.params.id)});
        if(data){
            if(data.url){
                let check=0;
                for(var key of data.url){
                    if(key.o_url == req.body.url){
                        check=1;
                        break;
                    }
                }
                if(check===1){
                    res.status(400).send("URL already exists");
                }
                else{
                    var sh_url = uniqid();
                    //insert into db with push
                    db.collection("users").updateOne({_id:objectId(req.params.id)},{$push:{url:{o_url:req.body.url,s_url:sh_url,count:0}}});
                    res.status(200).json({shorturl:sh_url,status:200});
                }
            }
            else{
                //create 
                var sh_url = uniqid();
                await db.collection("users").updateOne({_id:objectId(req.params.id)},{$set:{url:[{o_url:req.body.url,s_url:sh_url,count:0}]}});
                res.status(200).json({shorturl:sh_url,status:200});
            }
        }
        else{
            res.status(404).send("ID not found");
        }

    }
    catch (error) {
        console.log(error);
        res.status(500).json({
            message: "Internal Server Error",
        });
    }
});

app.put("/updatecount/:id",async(req,res)=>{
    try{
        let client = await mongoClient.connect(dbURL);
        let db = client.db(process.env.DB_NAME);
        await db.collection("users").updateOne({_id:objectId(req.params.id),"url.s_url":req.body.s_url},{$inc:{"url.$.count":1}});
        res.status(200).send("Succcess");
    }
    catch (error) {
        console.log(error);
        res.status(500).json({
            message: "Internal Server Error",
        });
    }
});

app.listen(port, () => console.log("App index.js is running on port:", port));