const jwt = require("jsonwebtoken");
const fetch = require("node-fetch");
//const getapi = require('../public/login')

async function getapi(url) {
  // Storing response
  const response = await fetch(url);
  // Storing data in form of JSON
  var data = await response.json();
    return data;
}



const requireAuth = (req, res, next) => {
  const token = req.cookies.jwt;
  //check if jwt exists and is verified

  if (token) {
    jwt.verify(token, "peepeePoopPoo", (err, decodedToken) => {
      if (err) {
        res.redirect("/login");
        console.log(err.message);
      } else {
        console.log(decodedToken);
        next();
      }
    });
  } else {
    res.redirect("/login");
  }
};


//check current user
const checkUser = (req, res, next) => {
  const token = req.cookies.jwt;

  if (token) {
    jwt.verify(token, "peepeePoopPoo", async (err, decodedToken) => {
      if (err) {
        console.log(err.message);
        res.locals.user = null;
        next();
      } else {
        console.log(decodedToken);
        user = null;
        data = await getapi("https://beakon-employee.herokuapp.com/employees");
        for (r = 0; r<data.length; r++){
            if (data[r]._id == decodedToken.id)
                {
                    user = data[r];  //finds email
                }
        }
        res.locals.user = user;
        next();
      }
    });
  } else {
    res.locals.user = null;
    next();
  }
};

module.exports = { requireAuth, checkUser };


