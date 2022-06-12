<?php include "functions.php"; 
    session_start();
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <?= style_script() ?>
    <title>Login</title>
</head>

<body class="text-center">
    <?php
    if(!isset($_SESSION['notif'])){
        $_SESSION['notif']="";
    }
    //generate csrf token
    $_SESSION['token'] = bin2hex(random_bytes(35));
    //token for CSRF
    $token = $_POST['token'];

    if ((!$token) || ($token != $_SESSION['token'])) {
        echo '<p class="error">Error: invalid form submission</p>';
        header($_SERVER['SERVER_PROTOCOL'] . ' 405 Method Not Allowed');
        exit;
    } 
    else{
        if (isset($_POST['username']) && isset($_POST['password'])) {
            $user = htmlentities($_POST['username']);
            $pass = htmlentities($_POST['password']);
            $pdo = pdo_connect();
            
            $stmt = $pdo->prepare('SELECT * FROM users WHERE username = ? LIMIT 1');
            $stmt->execute([$user]);
            $notif = $stmt->rowCount();
            $IP = getenv ( "REMOTE_ADDR" );

            if ($stmt->rowCount() > 0) {
                $userss = $stmt->fetch();
                $hash_salt = $userss['salted_pass'];
                if(password_verify($pass, $hash_salt )){
                    $_SESSION['user'] = $user;
                    header("location: index.php");
                } 
                else {
                    $_SESSION['notif'] = "Wrong usename or password";
                    header("location: login.php");
                }
            } 
            else {
                $notif = "Wrong usename or password";
            } 
        }
    }
    ?>
    <form class="form-signin" method="POST">
        <h1 class="h3 mb-3 font-weight-normal">Please sign in</h1>
        <label for="inputUsername" class="sr-only">Username</label>
        <input type="username" id="inputUsername" name="username" class="form-control" placeholder="Username" required autofocus>
        <br>
        <label for="inputPassword" class="sr-only">Password</label>
        <input type="password" id="inputPassword" name="password" class="form-control" placeholder="Password" required>
        <input type="hidden" name="token" value="<?=$_SESSION["token"]?>"/>
        <div class="checkbox mb-3">
            <label>
                <?php 
                    echo $_SESSION['notif'];
                ?>
            </label>
        </div>
        <button class="btn btn-lg btn-primary btn-block" type="submit">Sign in</button>
        <p class="mt-5 mb-3 text-muted">hk &copy; 2021</p>
    </form>
</body>

</html>