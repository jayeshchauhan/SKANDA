<html>
<body>
<h1>Enter the URL of an image on the Internet</h1>
<h3>This page uses the file_get_contents and file_put_contents PHP functions.</h3>
<form method="post" action="">
<input type=text name="url" id="url" size="50"/>
<input type="submit" class="button" value="submit" />
</form>

<?php
    
    if (isset($_POST['url']))
    {
    $content = file_get_contents($_POST['url']);
    $filename = './images/'.rand().'img1.jpg';
    file_put_contents($filename, $content);
    echo $_POST['url']."</br>";    
    $img = "<img src=\"".$filename."\"/>";
    }
    echo $img;
?>
<body>
</html>
