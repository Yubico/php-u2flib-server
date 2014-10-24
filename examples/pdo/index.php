<?php

require_once('../../vendor/autoload.php');

const TYPE_REG = 1;
const TYPE_AUTH = 2;

$dbfile = '/var/tmp/u2f-pdo.sqlite';

$pdo = new PDO("sqlite:$dbfile");
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_OBJ);

$pdo->exec("create table if not exists users (id integer primary key, name varchar(255))");
$pdo->exec("create table if not exists registrations (id integer primary key, user_id integer, keyHandle varchar(255), publicKey varchar(255), certificate text, counter integer)");

$scheme = isset($_SERVER['HTTPS']) ? "https://" : "http://";
$u2f = new u2flib_server\U2F($scheme . $_SERVER['HTTP_HOST']);

session_start();

function createAndGetUser($name) {
  global $pdo;
  $sel = $pdo->prepare("select * from users where name = ?");
  $sel->execute(array($name));
  $user = $sel->fetch();
  if(!$user) {
    $ins = $pdo->prepare("insert into users (name) values(?)");
    $ins->execute(array($name));
    $sel->execute(array($name));
    $user = $sel->fetch();
  }
  return $user;
}

function getRegs($user_id) {
  global $pdo;
  $sel = $pdo->prepare("select * from registrations where user_id = ?");
  $sel->execute(array($user_id));
  return $sel->fetchAll();
}

function addReg($user_id, $reg) {
  global $pdo;
  $ins = $pdo->prepare("insert into registrations (user_id, keyHandle, publicKey, certificate, counter) values (?, ?, ?, ?, ?)");
  $ins->execute(array($user_id, $reg->keyHandle, $reg->publicKey, $reg->certificate, $reg->counter));
}

function updateReg($reg) {
  global $pdo;
  $upd = $pdo->prepare("update registrations set counter = ? where id = ?");
  $upd->execute(array($reg->counter, $reg->id));
}

?>

<html>
<head>
<title>PHP U2F example</title>

<script src="chrome-extension://pfboblefjcgdjicmnffhdgionmgcdmne/u2f-api.js"></script>

<script>
<?php

if($_SERVER['REQUEST_METHOD'] === 'POST') {
  if(!$_POST['username']) {
    echo "alert('no username provided!');";
  } else if(!isset($_POST['action']) && !isset($_POST['register2']) && !isset($_POST['authenticate2'])) {
    echo "alert('no action provided!');";
  } else {
    $user = createAndGetUser($_POST['username']);

    if(isset($_POST['action'])) {
      if($_POST['action'] === 'register') {
        $data = $u2f->getRegisterData(getRegs($user->id));
        if(property_exists($data, "errorCode")) {
          echo "alert('error: " . $data->errorMessage . "');";
        } else {
          list($req,$sigs) = $data;
          $_SESSION['regReq'] = json_encode($req);
          echo "var req = " . json_encode($req) . ";";
          echo "var sigs = " . json_encode($sigs) . ";";
          echo "var username = '" . $user->name . "';";
?>
        setTimeout(function() {
            console.log("Register: ", req);
            u2f.register([req], sigs, function(data) {
                var form = document.getElementById('form');
                var reg = document.getElementById('register2');
                var user = document.getElementById('username');
                console.log("Register callback", data);
                if(data.errorCode) {
                    alert("registration failed with errror: " + data.errorCode);
                    return;
                }
                reg.value = JSON.stringify(data);
                user.value = username;
                form.submit();
            });
        }, 1000);
<?php
        }
      } else if($_POST['action'] === 'authenticate') {
        $reqs = json_encode($u2f->getAuthenticateData(getRegs($user->id)));
        if(property_exists($reqs, "errorCode")) {
          echo "alert('error: " . $reqs->errorMessage . "');";
        } else {
          $_SESSION['authReq'] = $reqs;
          echo "var req = $reqs;";
          echo "var username = '" . $user->name . "';";
?>
        setTimeout(function() {
            console.log("sign: ", req);
            u2f.sign(req, function(data) {
                var form = document.getElementById('form');
                var auth = document.getElementById('authenticate2');
                var user = document.getElementById('username');
                console.log("Authenticate callback", data);
                auth.value=JSON.stringify(data);
                user.value = username;
                form.submit();
            });
        }, 1000);
<?php
        }
      }
    } else if($_POST['register2']) {
      $reg = $u2f->doRegister(json_decode($_SESSION['regReq']), json_decode($_POST['register2']));
      $_SESSION['regReq'] = null;
      if(property_exists($reg, "errorCode")) {
        echo "alert('error: " . $reg->errorMessage . "');";
      } else {
        addReg($user->id, $reg);
      }
    } else if($_POST['authenticate2']) {
      $reg = $u2f->doAuthenticate(json_decode($_SESSION['authReq']), getRegs($user->id), json_decode($_POST['authenticate2']));
      $_SESSION['authReq'] = null;
      if(property_exists($reg, "errorCode")) {
        echo "alert('error: " . $reg->errorMessage . "');";
      } else {
        updateReg($reg);
        echo "alert('success: " . $reg->counter . "');";
      }
    }
  }
}
?>
</script>
</head>
<body>

<form method="POST" id="form">
username: <input name="username" id="username"/><br/>
register: <input value="register" name="action" type="radio"/><br/>
authenticate: <input value="authenticate" name="action" type="radio"/><br/>
<input type="hidden" name="register2" id="register2"/>
<input type="hidden" name="authenticate2" id="authenticate2"/>
<button type="submit">Submit!</button>
</form>

</body>
</html>
