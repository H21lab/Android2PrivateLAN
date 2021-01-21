# Android2PrivateLAN
Android App to tunnel access from HTTPs C&amp;C server into Private LAN

Published on DeepSec 2020 conference
https://deepsec.net/docs/Slides/2020/Security_Model_Of_Endpoint_Devices_Martin_Kacer.pdf

## Disclaimer

The application has been released as prove of concept to demonstrate that the Android application with INTERNET permissions only could allow access into private networks. Responsible disclosure has been performed to Android Security program on 05/2020. Author does not undertake any responsibility for misapplication or illegal use of the application. Program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY.

## Communication flow

```
# Laptop ----- (8080/tcp)-----> HTTP_server <----(443/https polling)---- Android device ------ (XXX/tcp) -------> Private IP
```

![](https://github.com/H21lab/Android2PrivateLAN/blob/main/docs/ssh_tunneling.gif)

## How to use
```
# 1. Copy the http_server script to some server with public IP
#    Create there cert.pem and key.pem and place it into ./http_server folder
#
# 2. Change the IP addresses towards this public IP in Android apps
#
# ON SERVER:
# 3. Run the script there
# cd ./http_server
# sudo python3 http_server.py
#
# 4. Run Android app 
# wait for back connects from Android apps towards http server
# 
# 5. Check connected devices
# find ./http_server/
#
# 6. Instruct the http server to tunnel traffic over the connected Android towards target machine in the private LAN where the android resides
# sudo touch ./http_server/XXX.XXX.XXX.XXX/192.168.1.100\:22
#
# ON YOUR LAPTOP:
# 7. Establish SSH tunnel to the opened listener towards server 
# ssh -L 127.0.0.1:8080:127.0.0.1:8080  username@hostname
#
# 8. Connect tu the tunnel from your machine. Example for SSH traffic:
# ssh admin@127.0.0.1 -p 8080
```

## Attribution

This code was created by Martin Kacer

Copyright 2020 H21 lab, All right reserved, https://www.h21lab.com

