<?php

 /* Copyright (c) 2014 Yubico AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

require_once('../vendor/autoload.php');

$scheme = isset($_SERVER['HTTPS']) ? "https://" : "http://";
$u2f = new u2flib_server\U2F($scheme . $_SERVER['HTTP_HOST']);

?>
<html>
<head>
<title>PHP U2F Demo</title>

<script src="chrome-extension://pfboblefjcgdjicmnffhdgionmgcdmne/u2f-api.js"></script>

<script>

function addRegistration(reg) {
    var existing = localStorage.getItem('u2fregistration');
    var data = null;
    if(existing) {
        data = JSON.parse(existing);
        if(Array.isArray(data)) {
            data.push(JSON.parse(reg));
        } else {
            data = null;
        }
    }
    if(data == null) {
        data = [JSON.parse(reg)];
    }
    localStorage.setItem('u2fregistration', JSON.stringify(data));
}

<?php

function fixupArray($data) {
    $ret = array();
    $decoded = json_decode($data);
    foreach ($decoded as $d) {
        $ret[] = json_encode($d);
    }
    return $ret;
}

if($_SERVER['REQUEST_METHOD'] === 'POST') {
    if(isset($_POST['startRegister'])) {
        $regs = fixupArray($_POST['registrations']);
        list($data, $reqs) = $u2f->getRegisterData($regs);
        echo "var request = $data;\n";
        echo "var signs = $reqs;\n";
?>
        setTimeout(function() {
            console.log("Register: ", request);
            u2f.register([request], signs, function(data) {
                var form = document.getElementById('form');
                var reg = document.getElementById('doRegister');
                var req = document.getElementById('request');
                console.log("Register callback", data);
                if(data.errorCode) {
                    alert("registration failed with errror: " + data.errorCode);
                    return;
                }
                reg.value=JSON.stringify(data);
                req.value=JSON.stringify(request);
                form.submit();
            });
        }, 1000);
<?php
    } else if($_POST['doRegister']) {
        $data = $u2f->doRegister($_POST['request'], $_POST['doRegister']);
        echo "var registration = '$data';\n";
?>
        if(registration != "") {
            addRegistration(registration);
            alert("registration successful!");
        } else {
            alert("registration failed!");
        }
<?php
    } else if(isset($_POST['startAuthenticate'])) {
        $regs = fixupArray($_POST['registrations']);
        $data = $u2f->getAuthenticateData($regs);
        echo "var registrations = " . $_POST['registrations'] . ";\n";
        echo "var request = $data;\n";
?>
        setTimeout(function() {
            console.log("sign: ", request);
            u2f.sign(request, function(data) {
                var form = document.getElementById('form');
                var reg = document.getElementById('doAuthenticate');
                var req = document.getElementById('request');
                var regs = document.getElementById('registrations');
                console.log("Authenticate callback", data);
                reg.value=JSON.stringify(data);
                req.value=JSON.stringify(request);
                regs.value=JSON.stringify(registrations);
                form.submit();
            });
        }, 1000);
<?php
    } else if($_POST['doAuthenticate']) {
        $reqs = fixupArray($_POST['request']);
        $regs = fixupArray($_POST['registrations']);
        $data = $u2f->doAuthenticate($reqs, $regs, $_POST['doAuthenticate']);
        echo "var auth = '$data';\n";
?>
        if(auth != "") {
            alert('Authentication successful, counter:' + auth);
        } else {
            alert('Authentication failed.');
        }
<?php
    }
}
?>
</script>

</head>
<body>
<form method="POST" id="form">
<button name="startRegister" type="submit">Register</button>
<input type="hidden" name="doRegister" id="doRegister"/>
<button name="startAuthenticate" type="submit" id="startAuthenticate">Authenticate</button>
<input type="hidden" name="doAuthenticate" id="doAuthenticate"/>
<input type="hidden" name="request" id="request"/>
<input type="hidden" name="registrations" id="registrations"/>
</form>
<script>
var reg = localStorage.getItem('u2fregistration');
if(reg == null) {
    var auth = document.getElementById('startAuthenticate');
    auth.disabled = true;
} else {
    var regs = document.getElementById('registrations');
    regs.value = reg;
    console.log("set the registrations to : ", reg);
}
</script>
</body>
</html>
