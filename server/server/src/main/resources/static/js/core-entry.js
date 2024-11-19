/**
* MIT License
*
* Copyright (c) 2020 Infineon Technologies AG
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE
*/

const alertTermsOfService = document.getElementById("alertTermsOfService");

window.onload = function() {
    console.log("website loaded");
    fCheckBrowser();
}

function fShowAlertTermsOfService() {
  alertTermsOfService.innerHTML = "<div class='alert alert-primary alert-dismissable mt-3'><button type='button' class='close' data-dismiss='alert' aria-hidden='true'>&times;</button>Please read the <a href='#idDisclaimer'>disclaimer</a></div>";
}

function fShowAlertNOKSignUp() {
  alertSignUp.innerHTML = "<div class='alert alert-danger alert-dismissable mt-3'><button type='button' class='close' data-dismiss='alert' aria-hidden='true'>&times;</button>Username is taken.</div>";
}

function fShowAlertOKSignUp() {
  alertSignUp.innerHTML = "<div class='alert alert-success alert-dismissable mt-3'><button type='button' class='close' data-dismiss='alert' aria-hidden='true'>&times;</button>Sign up sucessful, you may sign in now.</div>";
}

function fShowAlertNOKSignIn() {
  alertSignIn.innerHTML = "<div class='alert alert-danger alert-dismissable mt-3'><button type='button' class='close' data-dismiss='alert' aria-hidden='true'>&times;</button>Invalid username or password, try again.</div>";
}

function fShowAlertForgotPassword() {
  alertSignIn.innerHTML = "<div class='alert alert-danger alert-dismissable mt-3'><button type='button' class='close' data-dismiss='alert' aria-hidden='true'>&times;</button>Can't help you, just sign up a new account.</div>";
}

async function fSignUp() {
  var form = document.getElementById( "idFormSignUp" );
  var txJson = fFormToJSON( form );

  fWebApi('POST', 'signup', JSON.stringify(txJson), function (json) {
    console.log(json);
    if (json.status === RESP_OK) {
      fShowAlertOKSignUp();
    } else {
      fShowAlertNOKSignUp();
    }
  });
}

function fSignIn() {
  var form = document.getElementById( "idFormSignIn" );
  var txJson = fFormToJSON( form );

  fWebApi('POST', 'signin', JSON.stringify(txJson), function (json) {
    console.log(json);
    if (json.status === RESP_OK) {
      location.href = '/dashboard';
    } else {
      fShowAlertNOKSignIn();
    }
  });
}

function fSignOut() {
  fWebApi('GET', 'signout', null,function (json) {
    if (json.status === RESP_OK) {
      location.reload();
    }
  });
}
