const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const User = require("./models/User");

const app = express();
app.use(express.json());

mongoose.connect(process.env.MONGO_URI);

app.post("/api/register", async (req,res)=>{
  const hash = await bcrypt.hash(req.body.password,10);
  await User.create({ email:req.body.email, password:hash });
  res.json({ ok:true });
});

app.post("/api/login", async (req,res)=>{
  const user = await User.findOne({ email:req.body.email });
  if(!user) return res.sendStatus(401);

  const ok = await bcrypt.compare(req.body.password, user.password);
  if(!ok) return res.sendStatus(401);

  const token = jwt.sign({ id:user._id }, process.env.JWT_SECRET);
  res.json({ token });
});

app.listen(3000);
