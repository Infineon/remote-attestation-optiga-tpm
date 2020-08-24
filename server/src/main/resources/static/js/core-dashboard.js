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

window.onload = function() {
  console.log("website loaded");
  fCheckBrowser();
  fWebSocket_init();

  $("#ca-root-cert").val(caCerts.rootCAText);
  $("#ca-root-attest").val(caCerts.rootCAAttest);
  if (caCerts.rootCAAttest == "Passed") {
    $("#ca-root-attest").css({'background-color':'green'});
    $("#ca-root-attest").css({'color':'white'});
  } else {
    $("#ca-root-attest").css({'background-color':'red'});
    $("#ca-root-attest").css({'color':'white'});
  }

  $("#attune-sha1-pcrlist").val(attune.sha1Bank);
  $("#attune-sha2-pcrlist").val(attune.sha256Bank);
  $("#attune-pcrs-value").val(attune.pcrs);
  $("#attune-ak-pk").val(attune.akPub);
  $("#attune-ak-name").val(attune.akName);
  $("#attune-pcrs-value").val($("#attune-pcrs-value").val().toLowerCase());
  $("#attune-ak-pk").val($("#attune-ak-pk").val().toLowerCase())
  $("#attune-measure-list").val(attune.imaTemplate);
  $("#attune-ek-attest").val(attune.ekCrtAttest);
  $("#attune-ek-cert").val(attune.ekCrt);
  if (attune.ekCrtAttest == "Passed") {
    $("#attune-ek-attest").css({'background-color':'green'});
    $("#attune-ek-attest").css({'color':'white'});
  } else if (attune.ekCrtAttest != null) {
    $("#attune-ek-attest").css({'background-color':'red'});
    $("#attune-ek-attest").css({'color':'white'});
  }

  $("#atelic-qualification").val(atelic.qualification);
}

function fSignOut() {
  fWebApi('GET', 'signout', null,function (json) {
    if (json.status === RESP_OK) {
      location.href = '/entry';
    }
  });
}

function fWebSocket_init() {
  var stompClient = fWebSocket_connect( function(frame) {
    console.log('Connected: ' + frame);
    stompClient.subscribe('/topic/public-test', function (messageOutput) {
      console.log('Public: ');
      console.log(JSON.parse(messageOutput.body));
    });
    stompClient.subscribe('/user/topic/private-test', function (messageOutput) {
      console.log('Private: ');
      console.log(messageOutput.body);
      fRx(messageOutput.body);
    });
    stompClient.send("/app/private-test", {}, JSON.stringify({'from': 'me', 'text': "/app/private-test"}))
    stompClient.send("/app/public-test", {}, JSON.stringify({'from': 'me', 'text': "/app/public-test"}))
  });
}

function fRx(message) {
  try {
    message = JSON.parse(message);
    let data = message.data;
    let type = data.type;
    if (type == "attune-resp") {
      $("#attune-sha1-pcrlist").val(data.sha1Bank);
      $("#attune-sha2-pcrlist").val(data.sha256Bank);
      $("#attune-pcrs-value").val(data.pcrs);
      $("#attune-ak-pk").val(data.akPub);
      $("#attune-ak-pk").val($("#attune-ak-pk").val().toLowerCase());
      $("#attune-pcrs-value").val($("#attune-pcrs-value").val().toLowerCase());
      $("#attune-ak-name").val(data.akName);
      $("#attune-ak-name").val($("#attune-ak-name").val().toLowerCase());
      $("#attune-ek-attest").val(data.ekCrtAttest);
      $("#attune-ek-cert").val(data.ekCrt);
      $("#attune-measure-list").val(data.imaTemplate);
      if (data.ekCrtAttest == "Passed") {
        $("#attune-ek-attest").css({'background-color':'green'});
        $("#attune-ek-attest").css({'color':'white'});
      } else {
        $("#attune-ek-attest").css({'background-color':'red'});
        $("#attune-ek-attest").css({'color':'white'});
      }
    } else if (type == "atelic-resp") {
      $("#atelic-qualification").val(data.qualification);
      $("#atelic-qualification").val($("#atelic-qualification").val().toLowerCase());
    } else if (type == "attest-resp") {
      $("#attest-time").val(new Date(data.time));
      $("#attest-outcome").val(data.outcome);
      if (data.outcome == "Passed") {
        $("#attest-outcome").css({'background-color':'green'});
        $("#attest-outcome").css({'color':'white'});
      } else {
        $("#attest-outcome").css({'background-color':'red'});
        $("#attest-outcome").css({'color':'white'});
      }
      $("#attest-quote").val(data.quote);
      $("#attest-name").val(data.akName);
      $("#attest-name").val($("#attest-name").val().toLowerCase());
      $("#attest-clock").val(data.clock.toString(16) + " (" + data.clock + ")");
      $("#attest-firmware").val(data.firmware.toString(16));
      $("#attest-sha1-pcrlist").val(data.sha1Bank);
      $("#attest-sha2-pcrlist").val(data.sha256Bank);
      $("#attest-qualification").val(data.qualification);
      $("#attest-pcr-digest").val(data.digest);
      $("#attest-signature").val(data.signature);
      $("#attest-quote").val().toLowerCase();
      $("#attest-qualification").val($("#attest-qualification").val().toLowerCase());
      $("#attest-pcr-digest").val($("#attest-pcr-digest").val().toLowerCase());
      $("#attest-signature").val($("#attest-signature").val().toLowerCase());
      $("#attest-measure-list").val(data.measureList);
      $("#attest-compute-sha1-pcrlist").val(data.sha1BankCompute);
      $("#attest-compute-sha2-pcrlist").val(data.sha256BankCompute);
      $("#attest-expected-pcr-digest").val(data.expectedDigest);
      $("#attest-pcrs-value").val(data.pcrs);
    }
  } catch (err) {
    // ignore
  }
}
