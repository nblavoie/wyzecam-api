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

TBD.