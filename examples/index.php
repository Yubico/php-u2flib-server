<?php

require_once('../vendor/autoload.php');

$scheme = isset($_SERVER['HTTPS']) ? "https://" : "http://";
$u2f = new u2flib_server\U2F($scheme . $_SERVER['HTTP_HOST']);

?>
<html>
<head>
<title>PHP U2F Demo</title>

<script src="chrome-extension://pfboblefjcgdjicmnffhdgionmgcdmne/u2f-api.js"></script>

<script>
<?php
if($_SERVER['REQUEST_METHOD'] === 'POST') {
    if(isset($_POST['startRegister'])) {
        $data = $u2f->getRegisterData();
        echo "var request = $data;\n";
?>
        setTimeout(function() {
            console.log("Register: ", request);
            u2f.register([request], [], function(data) {
                var form = document.getElementById('form');
                var reg = document.getElementById('doRegister');
                var req = document.getElementById('request');
                console.log("Register callback", data);
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
            localStorage.setItem('u2fregistration', registration);
            alert("registration successful!");
        } else {
            alert("registration failed!");
        }
<?php
    } else if(isset($_POST['startAuthenticate'])) {
        $regs = array($_POST['registrations']);
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
                req.value=JSON.stringify(request[0]);
                regs.value=JSON.stringify(registrations);
                form.submit();
            });
        }, 1000);
<?php
    } else if($_POST['doAuthenticate']) {
        $reqs = array($_POST['request']);
        $regs = array($_POST['registrations']);
        $data = $u2f->doAuthenticate($reqs, $regs, $_POST['doAuthenticate']);
        echo "var auth = '$data';\n";
        if(auth != "") {
            echo "alert('Authentication successful, counter:' + auth);\n";
        } else {
            echo "alert('Authentication failed.');\n";
        }
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
    regs.value = [reg];
    console.log("set the registrations to : ", reg);
}
</script>
</body>
</html>
