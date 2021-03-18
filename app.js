const express = require("express");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
//router
const authRoutes = require("./routes/authRoutes");
const app = express();

//midleware
app.use(express.static('public'));



//veiw engine
app.set('view engine','ejs');

// database connection

const dbURI =
  "mongodb+srv://Nathan:TrlDs2mXMnPbjEAP@cluster0.a6xht.mongodb.net/node-auth";
  mongoose
  .connect(dbURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true,
  })
  .then((result) => app.listen(3000))
  .catch((err) => console.log(err));


//routes
app.get("/", (req, res) => res.render("index"));
app.get("/test", (req, res) => res.render("test"));
app.get('/faq',(req,res) => res.render("faq"))
app.get('/announcements',(req,res) => res.render("announcements"))
app.use(authRoutes);
