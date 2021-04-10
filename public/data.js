// api url
const api_url = 
      "https://beakon-employee.herokuapp.com/employees";
  
// Defining async function
async function getapi(url) {
    
    // Storing response
    const response = await fetch(url);
    
    // Storing data in form of JSON
    var data = await response.json();
    console.log(data);
    // if (response) {
    //     hideloader();
    // }
    show(data);
}
// Calling that async function
getapi("https://beakon-employee.herokuapp.com/employees");
  
// Function to hide the loader
function hideloader() {
    document.getElementById('loading').style.display = 'none';
}
// Function to define innerHTML for HTML table
function show(data) {
    let tab = 
        `<tr>
          <th>LastName</th>
          <th>FirstName</th>
          <th>Email</th>
          <th>workID</th>
         </tr>`;
    
    // Loop to access all rows 
    for (let r of data) {
        tab += `<tr> 
    <td>${r.lastName} </td>
    <td>${r.firstName}</td>
    <td>${r.email}</td> 
    <td>${r.workID}</td>          
    </tr>`;
    }
    // Setting innerHTML as tab variable
    document.getElementById("employees").innerHTML = tab;
}
