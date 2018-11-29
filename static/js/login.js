/*$(document).ready(function () {
    $(document).on("submit","#login-form", function (e) {
        e.preventDefault();
        console.log("Form Submitted");
        var form = $("#login-form").serialize();
        $.ajax({
            async: true,
            url: '/login',
            type: 'POST',
            data: form,
            success: function (response) {
                if (response == 'Invalid Details')
                {
                    alert("Enter correct info");
                }
                else
                {
                    window.location.href = response;
                }
            }
        });
    });

    $(document).on("submit","#register-form", function (e) {
        e.preventDefault();
        console.log("Form Submitted");
        var form = $("#register-form").serialize();
        $.ajax({
            async: true,
            url: '/register',
            type: 'POST',
            data: form,
            success: function (response) {
                alert(response);
            }
        });
    });

    $(document).on("submit","#device-form", function (e) {
        e.preventDefault();
        console.log("Form Submitted");
        var form = $("#device-form").serialize();
        $.ajax({
            async: true,
            url: '/registerdev',
            type: 'POST',
            data: form,
            success: function (response) {
                alert(response);
            }
        });
    });
}); */

let x = document.getElementsByClassName("myid");
for (i = 0; i < x.length; i++) {
    console.log(x.innerText);
if (x[i].innerText == "Secure")
{
    x[i].style.color = "Green";
}
else
{
    x[i].style.color = "Red";
}
}


var form = document.getElementById('register-form');

function myFunction() {
  if (form.checkValidity()) {
    alert("Registration completed Succesfully");
  }
}

let password = document.getElementById("passw");
let confirm_password = document.getElementById("re_pass");

function validatePassword(){
  if(password.value != confirm_password.value) {
    confirm_password.setCustomValidity("Passwords Don't Match");
  } else {
    confirm_password.setCustomValidity('');
  }
}

password.onchange = validatePassword;
confirm_password.onkeyup = validatePassword;
