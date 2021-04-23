const fetch = require("node-fetch");
const bcrypt = require('bcrypt');

// api url
const api_url = "https://beakon-employee.herokuapp.com/employees";

// Defining async function
async function getapi(url) {
  // Storing response
  const response = await fetch(url);
  // Storing data in form of JSON
  var data = await response.json();
    return data;
}
// Calling that async function
//getapi("https://beakon-employee.herokuapp.com/employees");
//data = getapi(api_url);



const login_fun = async function (email,password){
    user = null;
    data = await getapi("https://beakon-employee.herokuapp.com/employees");
    for (r = 0; r<data.length; r++){
        if (data[r].email == email)
            {
                user = data[r];  //finds email
            }
        console.log(user)
    }
    if(user) {  //if email exists
        const auth = await bcrypt.compare(password, user.password) //check if password is correct
        if (auth){ //if it is, return the user
            return user;
        }
        throw Error('incorrect password') //wrong password
    }
    throw Error('incorrect email') // nonexistant email
}

module.exports = login_fun;
