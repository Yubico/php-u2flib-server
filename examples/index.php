<?php

require_once('../vendor/autoload.php');

$u2f = new u2flib_server\U2F($_SERVER['HTTP_HOST']);

?>

<html>
<head>
<title>PHP U2F Demo</title>

<script src="chrome-extension://pfboblefjcgdjicmnffhdgionmgcdmne/u2f-api.js"></script>

<?php

?>

</head>
<body>
<form id="register" method="POST">
<button>Register</button>
</form>
<form id="authenticate" method="POST">
<button id="authenticate">Authenticate</button>
</form>
</body>
</html>
