# Wyzecam API (unofficial, reverse engineered for experimental use only).

# Note: May 15 2019: Project has been discontinued.
- ### Wyze now provides RTSP firmware which can be installed to allow you to stream video from WyzeCams. Info @ https://support.wyzecam.com/hc/en-us/articles/360026245231-Wyze-Cam-RTSP
- ### Wyze does not yet provide a general API/SDK for developers. Users have requested this and Wyze's current response [is available here](https://forums.wyzecam.com/t/api-for-developers/32845)


---
<br/>


Wyzecams are awesome. At 19$, these are the perfect Wi-Fi cameras. They are reliable, well built and the Wyzecam mobile app is well made. But, the mobile application lacks a feature I really need: a way to access the cameras feed outside its walled garden. This repository is my attempt to document the Wyzecam API protocol to locally get my cameras feed in a cross-platform desktop application.

Feel free to participate, issue pull requests, etc.

**Disclaimer : This repository is for fun only. WizeLabs is a wonderful company, do no harm and be civilized.**

URL : [https://api.wyzecam.com:8443](https://api.wyzecam.com:8443)

## 1. Login method.

URL POST: [https://api.wyzecam.com:8443](https://api.wyzecam.com:8443/app/user/login)

JSON payload : 

```json
{
    "sc": "f5609af3fa9541fd82a486df5fd9965a",
    "sv": "1ee66ee1fe03403b9ded3fe2fa869f2a",
    "app_ver": "com.hualai___1.1.52",
    "ts": 1524247514196,
    "access_token": "",
    "phone_id": "bc151f39-787b-4871-be27-5a20fd0a1937",
    "user_name": "email@domain.com",
    "password": "password"
}
```

Field Key  | Field Type | Details
------------- | ------------- | -------------
sc  | String (32 char length) | TBD.
sv  | String (32 char length) | TBD.
app_ver | String | Mobile app version. Curently using ```com.hualai___1.1.52```.
ts | Time | Current time in milliseconds.
access_token | String | For the login request, this field is empty. Upon a successful login, the access_token will be returned as a JSON value (see ```data.access_token``` in the next section).
phone_id | GUID | A unique phone identifiant. For that purpose, you [may generate a new GUID](https://www.guidgenerator.com/). As example, here is a valid GUID : ```bc151f39-787b-4871-be27-5a20fd0a1937```.
user_name | String | Your Wyzecam email.
password | String | Your Wyzecam password. Hash is made of ```MD5(MD5(password))```.


Example with cURL :

```curl
curl -H "Content-Type: application/json" -X POST -d '{"sc":""f5609af3fa9541fd82a486df5fd9965a",","sv":""1ee66ee1fe03403b9ded3fe2fa869f2a",","app_ver":"com.hualai___1.1.52","ts":1524248711789,"access_token":"","phone_id":"bc151f39-787b-4871-be27-5a20fd0a1937","user_name":"email@domain.com","password":"password"}' https://api.wyzecam.com:8443/app/user/login
```

JSON response example :


```json
{
   "ts":1524249332073,
   "code":"1",
   "msg":"",
   "data":{
      "access_token":"access token",
      "refresh_token":"refresh token"
   }
}

```

JSON login error :


```json
TBD

```

JSON account locked error :

```json
TBD

```

## 2. List devices (get list of cameras).

URL: POST https://api.wyzecam.com:8443/app/device/get_device_list

JSON payload:
```json
{
	"sv": "01463873df804629b15694df13126d31",
	"sc": "01dd431d098546f9baf5233724fa2ee2",
	"ts": 1525365683583,
	"app_ver": "com.hualai.WyzeCam___1.3.116",
	"phone_id": "bc151f39-787b-4871-be27-5a20fd0a1937",
	"access_token": "ACQUIRED_AT_LOGIN"
}
```


Field Key  | Field Type | Details
------------- | ------------- | -------------
sc  | String (32 char length) | TBD.
sv  | String (32 char length) | TBD.
app_ver | String | Mobile app version. Curently using ```com.hualai___1.1.52```.
ts | Time | Current time in milliseconds.
access_token | String | An access token acquired at login. (see ```data.access_token```).
phone_id | GUID | A unique phone identifiant. For that purpose, you [may generate a new GUID](https://www.guidgenerator.com/). As example, here is a valid GUID : ```bc151f39-787b-4871-be27-5a20fd0a1937```.

Example with cURL:
```
    curl -H 'Host: api.wyzecam.com:8443' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'User-Agent: HLHome/1.3.116 (iPhone; iOS 11.3; Scale/3.00)' -H 'Accept-Language: en-US;q=1' --data-binary '{"sv":"01463873df804629b15694df13126d31","sc":"01dd431d098546f9baf5233724fa2ee2","ts":1525365683583,"app_ver":"com.hualai.WyzeCam___1.1.52","phone_id":"bc151f39-787b-4871-be27-5a20fd0a1937","access_token":"ACQUIRED_AT_LOGIN"}' --compressed 'https://api.wyzecam.com:8443/app/device/get_device_list'
```

JSON response example:
```
{
	"ts": 1525365690660,
	"code": "1",
	"msg": "",
	"data": {
		"device_info_list": [{
			"mac": "CAMERA_MAC_ADDRESS",
			"enr": "TBD",
			"p2p_id": "PEER_TO_PEER_IDENTIFIER",
			"p2p_type": 3,
			"product_model": "WYZEC1-JZ",
			"product_type": "Camera",
			"hardware_ver": "0.0.0.0",
			"firmware_ver": "4.9.1.42",
			"role": 1,
			"nickname": "LilCam",
			"device_logo": "",
			"device_timezone": "",
			"binding_user_nickname": "ACCOUNT_EMAIL_ADDRESS",
			"ssid": "CAMERA_CONNECTED_WIFI_SSIDE",
			"ip": "CAMERA_IP_ADDRESS",
			"conn_state": 1,
			"power_switch": 1
		}],
		"device_sort_list": [{
			"device_id": "CAMERA_ID",
			"product_model": "WYZEC1-JZ"
		}]
	}
}
```

## URLs to document:

* https://api.wyzecam.com:8443/app/device/get_alarm_info_list
* https://api.wyzecam.com:8443/app/device/get_share_info_list
* https://api.wyzecam.com:8443/app/system/get_allow_binding_device_list
* https://api.wyzecam.com:8443/app/system/set_app_info
* https://api.wyzecam.com:8443/app/device/upload_device_connect_info
* https://api.wyzecam.com:8443/app/user/get_user_info
* https://api.wyzecam.com:8443/app/user/refresh_token
* https://api.wyzecam.com:8443/app/user/use_app
