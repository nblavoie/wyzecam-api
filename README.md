# Wyzecam API (unofficial, reverse engineered for experimental use only).

Wyzecams are awesome. At 19$, these are the perfect Wi-Fi cameras. They are reliable, well built and the Wyzecam mobile app is well made. But, the mobile application lacks a feature I really need: a way to access the cameras feed outside its walled garden. This repository is my attempt to document the Wyzecam API protocol to locally get my cameras feed in a cross-platform desktop application.

Feel free to participate, issue pull requests, etc.

**Disclaimer : This repository is for fun only. WizeLabs is a wonderful company, do no harm and be civilized.**

URL : [https://api.wyzecam.com:8443](https://api.wyzecam.com:8443)

## 1. Login method.

URL: [https://api.wyzecam.com:8443](https://api.wyzecam.com:8443/app/user/login)

JSON payload : 

```json
{
    "sc": "???",
    "sv": "???",
    "app_ver": "com.hualai___1.1.52",
    "ts": 1524247514196,
    "access_token": "",
    "phone_id": "phone guid",
    "user_name": "email@domain.com",
    "password": "password"
}
```

Field Key  | Field Type | Details
------------- | ------------- | -------------
sc  | String (32 char length) | Probably a secret hash.
sv  | String (32 char length) | TBD.
app_ver | String | Mobile app version. Curently using ```com.hualai___1.1.52```.
ts | Timestamp | Current timestamp in UTC.
access_token | String | For the login request, this field is empty. Upon a successful login, the access_token will be returned as a JSON value (see ```data.access_token``` in the next section).
phone_id | GUID | A unique phone identifiant.
user_name | String | Your Wyzecam email.
password | String | Algorithm to be defined (32 char length. MD5 ??).


Example with cURL :

```curl
curl -H "Content-Type: application/json" -X POST -d '{"sc":""???",","sv":""???",","app_ver":"com.hualai___1.1.52","ts":1524248711789,"access_token":"","phone_id":"phone guid","user_name":"email@domain.com","password":"password"}' https://api.wyzecam.com:8443/app/user/login
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

TBD.