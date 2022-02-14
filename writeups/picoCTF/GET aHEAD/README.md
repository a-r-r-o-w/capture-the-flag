
# GET aHEAD 

### Author: madStacks

### Description

```
Category: Web Exploitation

Find the flag being held on this server to get ahead of the competition <a href="http://mercury.picoctf.net:21939/">http://mercury.picoctf.net:21939/</a>

Hints:

(1) Maybe you have more than 2 choices

(2) Check out tools like Burpsuite to modify your requests and look at the responses

```

### Solution

The problem name has GET and HEAD in capitals. This probably hints towards GET request over http and taking a look at headers of the response. The GET request just returns the content of the webpage.

```bash
┌──(arrow) 💀 [~/…/capture-the-flag/Writeups/picoCTF/GET aHEAD]
└─$ curl -X GET http://mercury.picoctf.net:21939/                             

<!doctype html>
<html>
<head>
    <title>Red</title>
    <link rel="stylesheet" type="text/css" href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css">
	<style>body {background-color: red;}</style>
</head>
	<body>
		<div class="container">
			<div class="row">
				<div class="col-md-6">
					<div class="panel panel-primary" style="margin-top:50px">
						<div class="panel-heading">
							<h3 class="panel-title" style="color:red">Red</h3>
						</div>
						<div class="panel-body">
							<form action="index.php" method="GET">
								<input type="submit" value="Choose Red"/>
							</form>
						</div>
					</div>
				</div>
				<div class="col-md-6">
					<div class="panel panel-primary" style="margin-top:50px">
						<div class="panel-heading">
							<h3 class="panel-title" style="color:blue">Blue</h3>
						</div>
						<div class="panel-body">
							<form action="index.php" method="POST">
								<input type="submit" value="Choose Blue"/>
							</form>
						</div>
					</div>
				</div>
			</div>
		</div>
	</body>
</html>
```

Taking a look at the headers of the response, we get the flag.

```bash
┌──(arrow) 💀 [~/…/capture-the-flag/Writeups/picoCTF/GET aHEAD]
└─$ curl http://mercury.picoctf.net:21939/ --head
HTTP/1.1 200 OK
flag: picoCTF{r3j3ct_th3_du4l1ty_6ef27873}
Content-type: text/html; charset=UTF-8
```

##### Flag: `picoCTF{r3j3ct_th3_du4l1ty_6ef27873}`
