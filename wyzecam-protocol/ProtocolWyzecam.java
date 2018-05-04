package com.alexvas.dvr.protocols;

import android.content.Context;
import android.os.Build;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Log;

import com.alexvas.dvr.R;
import com.alexvas.dvr.conn.HttpHeader;
import com.alexvas.dvr.core.CameraSettings;
import com.alexvas.dvr.ptz.PtzListener;
import com.alexvas.dvr.utils.NetUtils;
import com.alexvas.dvr.utils.StringUtils;
import com.alexvas.dvr.utils.Utils;
import com.alexvas.dvr.video.VideoReceiveListener;
import com.alexvas.dvr.watchdog.WatchdogListener;
import com.tutk.IOTC.AVAPIs;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.IntBuffer;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Locale;
import java.util.TimeZone;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

// Login
// POST /app/user/login HTTP/1.1
//Content-Type: application/json
//Content-Length: 424
//User-Agent: Dalvik/1.6.0 (Linux; U; Android 4.3; Nexus 4 Build/JWR66Y)
//Host: api.wyzecam.com:8443
//Connection: Keep-Alive
//Accept-Encoding: gzip

//{
//        "sc":"f5609af3fa9541fd82a486df5fd9965a",
//        "sv":"1ee66ee1fe03403b9ded3fe2fa869f2a",
//        "app_ver":"com.hualai___1.1.52",
//        "ts":1513068666989,
//        "access_token":"",
//        "phone_id":"2604fcf8-dba8-45ce-9f14-4cafbd8b6f70",
//        "user_name":"343434@mail.ru",
//        "password":"0b04beb06f3e0bdc6f99e91070fb987a"
//}

//{
//    "user_name":"343434@mail.ru",
//    "ts":1513060153726,
//    "phone_id":"5c7fef03-d320-4082-8c78-6b19c26748dc",
//    "sv":"1ee66ee1fe03403b9ded3fe2fa869f2a",
//    "sc":"f5609af3fa9541fd82a486df5fd9965a",
//    "password":"0b04beb06f3e0bdc6f99e91070fb987a",
//    "access_token":"lvtx.orMsXlt+Og4cNDxinLyUDVAv0rFX382w0VQ\/UuRXurCRQTSKc+7g6RJTP2toFed0OI4NCbwehtmz+KW8Njd6Oe9RTQBgfRhhawfryQfiClDn2KLYeuAU4Q9hW415XiioxlCdRicePgk=",
//    "app_ver":"com.hualai___1.1.52"
//}

// POST /app/device/get_device_list HTTP/1.1
//{
//    "sv":"527f57974f7b4cea9810b90a66b42b6c",
//    "sc":"f5609af3fa9541fd82a486df5fd9965a",
//    "ts":1513060154661,
//    "phone_id":"5c7fef03-d320-4082-8c78-6b19c26748dc",
//    "access_token":"lvtx.5f7\/Lg7G6dDNuw0f4XA3fWFpuKYtVt3BIvlIAwjw3sJSptOY653nHPWUDlfrClB5bVbwcZoV5uY3gyWwMms+xNu1YyR4Aft3jZHsm3WqUzlrA1G+QTxdK9iaXU62h5+mT+5kAPGC0JI=",
//    "app_ver":"com.hualai___1.1.52"
//}

public class ProtocolWyzecam extends ProtocolP2pTutk {

    static final String TAG = ProtocolWyzecam.class.getSimpleName();
    static final boolean DEBUG = false;

    private static final int IOTYPE_USER_DEFINED_START = 256;
    private static final String APP_VERSION = "com.hualai___1.1.52";
    private static final String PHONE_ID = UUID.randomUUID().toString();

    private static class WyzecamInfo {
        String uid = null;
        String mac = null;
        String enr = null;
        long timestamp;
    }

    // Key - username:password
    // Value - list of devices
    private static final HashMap<String, ArrayList<WyzecamInfo>> g_cachedWyzecamInfo = new HashMap<>();

    private WyzecamInfo _info = new WyzecamInfo();

    private static class UnauthorizedException extends IOException {
        private static final long serialVersionUID = 1L;
        UnauthorizedException() {
            super();
        }
    }

    public ProtocolWyzecam(
            Context          context,
            CameraSettings   cameraSettings,
            int              threadType,
            WatchdogListener watchdogListener) {
        super(context, cameraSettings, threadType, watchdogListener);
    }

    @Override
    protected void onMainThreadStarted() {
        if (DEBUG)
            Log.v(TAG, "onMainThreadStarted()");
        init();
    }

    @Override
    protected void onMainThreadMsgReceived(int avIndex, int msgType, @NonNull byte[] buffer, int bufferLength) {
        if (msgType == IOTYPE_USER_DEFINED_START) {
            CamProtocolUtils res = CamProtocolUtils.getFromBytes(buffer);
            if (res == null)
                return;
            Log.d(TAG, "[WyzeCam] Msg " + res.getCode());
            switch (res.getCode()) {
                case 10001:
//                    if (DEBUG)
//                        Log.d(TAG, "[Wyzecam] Msg 10001" + ByteOperator.byteArrayToHexString(res.getData()));
                    if (res.getData() != null && res.getDataLength() >= 17) {
                        if (res.getData()[0] == (byte) 1 || res.getData()[0] == (byte) 3) {
                            byte[] cameraEnrB = new byte[16];
                            System.arraycopy(res.getData(), 1, cameraEnrB, 0, 16);
                            String cameraSecretKey = "FFFFFFFFFFFFFFFF";
                            String savedKey = _info.enr;//ConnectControl.instance().getEnr();
                            if (DEBUG) {
                                Log.d(TAG, "[WyzeCam] 10001 - Received enr: " + savedKey);
                                Log.d(TAG, "[WyzeCam] 10001 - Received uid: " + _info.uid);
                            }
                            if (res.getData()[0] == (byte) 3) {
                                if (savedKey.length() >= 16) {
                                    cameraSecretKey = savedKey.substring(0, 16);
                                    if (DEBUG)
                                        Log.d(TAG, "[WyzeCam] 10001 - Key to verify R: " + cameraSecretKey);
                                } else {
                                    Log.d(TAG, "[WyzeCam] 10001 - cameraSecret < 16");
                                }
                            }
                            if (cameraSecretKey.equals("")) {
                                Log.d(TAG, "[WyzeCam] 10001 - Command failed");
                                return;
                            }
                            byte[] r;
                            try {
                                r = ByteOperator.reverseByteArray(
                                        XXTEA.decrypt(
                                                ByteOperator.reverseByteArray(cameraEnrB),
                                                ByteOperator.reverseByteArray(cameraSecretKey.getBytes())));
                            } catch (Exception ex) {
                                ex.printStackTrace();
                                return;
                            }
                            byte[] data = CamCommand.K10002_connectAuth(
                                    r,
                                    _info.mac,
                                    true,
                                    true);
                            sendData(avIndex, data);
//                            CommandInfo cmd10002 = new CommandInfo(
//                                    10002,
//                                    CamCommand.K10002_connectAuth(r, _mac, true, true),
//                                    ConnectControl.instance().getP2pID(), deviceMac);
//                            if (cmd10002 != null && cmd10002.getResponseCode() > 0) {
//                                ConnectControl.cameraCmd.add(cmd10002);
//                                Log.d("CommandTreatment ", "10002 接收信息的队列一共有：" + ConnectControl.cameraCmd.size());
//                            }
//                            if (!TUTKAVModel.instance().sendData(cmd10002)) {
//                                Log.i("CommandTreatment ", "10002 发送失败");
//                                this.handler.obtainMessage(MessageIndex.CONNECTION_BREAK).sendToTarget();
//                                return;
//                            }
                        } else if (res.getData()[0] == (byte) 2) {
                            Log.i(TAG, "[WyzeCam] 10001 - Camera is updating");
                        } else if (res.getData()[0] == (byte) 4) {
                            Log.i(TAG, "[WyzeCam] 10001 - Camera is checking enr");
                        } else {
                            Log.e(TAG, "[WyzeCam] 10001 - Received unknown command");
                        }
                    }
                    break;

//{
//    "connectionRes":"1",
//    "cameraInfo":{
//        "videoParm":{
//            "bitRate":"30",
//            "resolution":"1",
//            "fps":"10",
//            "horizontalFlip":"1",
//            "verticalFlip":"1"
//        },
//        "settingParm":{
//            "stateVision":"1",
//            "nightVision":"3",
//            "osd":"1",
//            "logSd":"1",
//            "logUdisk":"1",
//            "telnet":"2",
//            "tz":"-8"
//        },
//        "basicInfo":{
//            "firmware":"3.9.1.84",
//            "type":"Camera",
//            "hardware":"0.0.0.0",
//            "model":"WYZEC1",
//            "mac":"94513D02A5E3"
//        },
//        "channelResquestResult":{
//            "video":"1",
//            "audio":"1"
//        },
//        "recordType":{
//            "type":"1"
//        },
//        "sdParm":{
//            "status":"1",
//            "capacity":"30424",
//            "free":"1430"
//        },
//        "uDiskParm":{
//            "status":"2",
//            "capacity":"0",
//            "free":"0"
//        }
//    }
//}
//                case 10003: {
//                    if (DEBUG)
//                        Log.d(TAG, "[WyzeCam] Msg 10003");
//                    String content = new String(res.getData());
//                    Log.i(TAG, "[10003] " + content);
//                    try {
//                        JSONObject jsonObject = new JSONObject(content);
//                        String macP2p = jsonObject.getJSONObject("cameraInfo").getJSONObject("basicInfo").getString("mac");
//                        Log.d(TAG, "[10003] MAC address obtained via P2P: " + macP2p);
//                    } catch (JSONException e) {
//                        e.printStackTrace();
//                    }
//                }
//                break;

                default:
                    Log.d(TAG, "[WyzeCam] Msg " + res.getCode());
            }
        }
    }

    @Override
    protected String getP2pUid() {
        return _info.uid;
    }

    @Override
    protected String getP2pUsername() {
        return _info.mac;
    }

    @Override
    protected String getP2pPassword() {
        return _info.mac;
    }

    @Override
    protected void onMainThreadConnectionEstablished(int avIndex) {
        byte[] data = CamCommand.K10000_connectRequest();
        sendData(avIndex, data);
    }

    private void sendData(int avIndex, @NonNull byte[] data) {
        int ret = AVAPIs.avSendIOCtrl(avIndex, IOTYPE_USER_DEFINED_START, data, data.length);
        if (ret < 0) {
            Log.e(TAG, "avSendIOCtrl failed: " + ret);
        }
    }

    // {"ts":1513070279382,"code":"1","msg":"","data":{}}
    private static void checkServerResult(@NonNull JSONObject jsonObject) throws IOException, JSONException {
        int code = StringUtils.toInteger(jsonObject.getString("code"), -1);
        String msg = jsonObject.getString("msg");
        switch (code) {
            // Success
            case 1: break;
            // UserNameOrPasswordError
            case 2000: throw new UnauthorizedException();
            default: throw new IOException("WyzeCam service failed with code " + code + " (" + msg + ")");
        }
        // 3000 - PhoneInfoNotExist
    }

    private static WyzecamInfo getWyzecamInfo(
            @NonNull Context context,
            @NonNull CameraSettings cameraSettings)
    throws Exception {
        if (DEBUG)
            Log.v(TAG, "getWyzecamInfo()");
        String key = cameraSettings.username + ":" + cameraSettings.password;
        synchronized (g_cachedWyzecamInfo) {
            int i = Math.max(0, cameraSettings.channel - 1);
            ArrayList<WyzecamInfo> devices = g_cachedWyzecamInfo.get(key);
            if (devices != null && i < devices.size()) {
                WyzecamInfo info = devices.get(i);
                if (System.currentTimeMillis() - info.timestamp > TimeUnit.HOURS.toMillis(1)) {
                    Log.d(TAG, "[WyzeCam] Cached devices info is old. New one will be requested.");
                } else {
                    Log.d(TAG, "[WyzeCam] Found cached devices info");
                    return info;
                }
            }

            Log.d(TAG, "[WyzeCam] No cached devices found for account " + cameraSettings.username + " channel " + cameraSettings.channel +
                    ". Requesting info from WyzeCam service...");
            devices = getWyzecamDevices(context, cameraSettings);
            if (devices == null) {
                String msg = "No WyzeCam cameras attached to account " + cameraSettings.username;
                Log.i(TAG, msg);
                throw new Exception(msg);
            }

            if (i >= devices.size())
                throw new Exception("Channel " + cameraSettings.channel + " is bigger than the number of available WyzeCam cameras " + devices.size());

            // Update cached list
            g_cachedWyzecamInfo.put(key, devices);
            return devices.get(i);
        }
    }

    @Nullable
    private static ArrayList<WyzecamInfo> getWyzecamDevices(
        @NonNull Context context,
        @NonNull CameraSettings cameraSettings)
    throws Exception {
        if (DEBUG)
            Log.v(TAG, "getWyzecamDevices()");

        // https://api.wyzecam.com:8443/app/system/set_app_info
        Log.d(TAG, "[WyzeCam] Setting app info...");
        JSONObject jsonObject = systemSetAppInfo();
        String postData = jsonObject.toString();
        String result = connect(context, cameraSettings, getAbsoluteUrl(URL_SET_APP_INFO), postData);
        if (DEBUG)
            Log.d(TAG, "" + result);
        jsonObject = new JSONObject(result);
        checkServerResult(jsonObject);

        // https://api.wyzecam.com:8443/app/user/login
        Log.d(TAG, "[WyzeCam] Starting login...");
        jsonObject = userLogin(cameraSettings.username, cameraSettings.password);
        postData = jsonObject.toString();
        result = connect(context, cameraSettings, getAbsoluteUrl(URL_LOGIN), postData);
        if (DEBUG)
            Log.d(TAG, "" + result);
        jsonObject = new JSONObject(result);
        checkServerResult(jsonObject);
        jsonObject = jsonObject.getJSONObject("data");
        String accessToken = jsonObject.getString(KEY_TOKEN_ACCESS);
        String refreshToken = jsonObject.getString(KEY_TOKEN_REFRESH);
        Log.i(TAG, "[WyzeCam] access token: " + accessToken);
        Log.i(TAG, "[WyzeCam] refresh token: " + refreshToken);

// https://api.wyzecam.com:8443/app/device/get_device_list
//{
//    "ts":1513246747543,
//    "code":"1",
//    "msg":"",
//    "data":{
//        "device_info_list":
//        [{
//            "mac":"94513D02A5E3",
//            "enr":"mlIHfqq2Nx9E6Cfg",
//            "p2p_id":"KHCGG3X9HA55TED1111A",
//            "p2p_type":4,
//            "product_model":"WYZEC1",
//            "product_type":"Camera",
//            "hardware_ver":"0.0.0.0",
//            "firmware_ver":"3.9.1.84",
//            "role":2,
//            "nickname":"Frederick Cam",
//            "device_logo":"",
//            "device_timezone":"America/Los_Angeles",
//            "binding_user_nickname":"Gwendolyn the Magnificent",
//            "ssid":"Autel Guest LW",
//            "ip":"192.168.1.244",
//            "conn_state":1,
//            "power_switch":1
//        }]
//    }
//}
        Log.d(TAG, "[WyzeCam] Getting device list...");
        jsonObject = getDeviceList(accessToken);
        postData = jsonObject.toString();
        result = connect(context, cameraSettings, getAbsoluteUrl(URL_GET_DEVICE_LIST), postData);
        if (DEBUG)
            Log.d(TAG, "" + result);
        jsonObject = new JSONObject(result);
        checkServerResult(jsonObject);
        JSONArray devices = jsonObject.getJSONObject("data").getJSONArray("device_info_list");
        if (devices.length() == 0)
            return null;
        ArrayList<WyzecamInfo> list = new ArrayList<>();
        for (int i = 0; i < devices.length(); i++) {
            WyzecamInfo info = new WyzecamInfo();
            jsonObject = devices.getJSONObject(i);
            info.uid = jsonObject.getString("p2p_id");
            info.mac = jsonObject.getString("mac");
            info.enr = jsonObject.getString("enr");
            info.timestamp = System.currentTimeMillis();
            Log.i(TAG, "WyzeCam uid: " + info.uid + ", mac: " + info.mac + ", enr: " + info.enr);
//                for (int i = 0; i < devices.length(); i++) {
//                    Log.i(TAG, "Device: " + devices.get(i));
//                    _uid = jsonObject.getString("p2p_id");
//                }
            list.add(info);
        }
        return list;

//        if (devices.length() > 0) {
//            if (cameraSettings.channel > devices.length())
//                throw new Exception("Channel is bigger than " + cameraSettings.channel);
//            int i = Math.max(0, cameraSettings.channel - 1);
//            jsonObject = devices.getJSONObject(i);
//            _info.uid = jsonObject.getString("p2p_id");
//            _info.mac = jsonObject.getString("mac");
//            _info.enr = jsonObject.getString("enr");
//            Log.i(TAG, "WyzeCam uid: " + _info.uid + ", mac: " + _info.mac + ", enr: " + _info.enr);
////                for (int i = 0; i < devices.length(); i++) {
////                    Log.i(TAG, "Device: " + devices.get(i));
////                    _uid = jsonObject.getString("p2p_id");
////                }
//        } else {
//            String msg = "No WyzeCam cameras attached to account " + cameraSettings.username;
//            Log.i(TAG, msg);
//            throw new Exception(msg);
//        }
    }

    private void init() {
        if (DEBUG)
            Log.v(TAG, "init()");

        try {
            _info = getWyzecamInfo(_context, _cameraSettings);
        } catch (UnauthorizedException e) {
            String errorDescr = String.format(_context.getString(R.string.error_video_failed1), _context.getString(R.string.error_unauthorized));
            _videoReceiveListener.onVideoReceiveError(VideoReceiveListener.ErrorType.ERROR_UNAUTHORIZED, errorDescr);
        } catch (Exception e) {
            _videoReceiveListener.onVideoReceiveError(VideoReceiveListener.ErrorType.ERROR_FATAL, e.getMessage());
            // HACK: Show message on screen for 8 seconds
            Utils.sleep(8000);
        }
    }

    @Nullable
    private static String connect(
            @NonNull Context context,
            @NonNull CameraSettings cameraSettings,
            @NonNull String url,
            @NonNull String postData)
    throws IOException {
        if (DEBUG)
            Log.v(TAG, "connect(url=\"" + url + "\", postData=\"" + postData + "\")");

        ArrayList<HttpHeader> headers = new ArrayList<>();
        headers.add(new HttpHeader("Content-Type", "application/json"));
        headers.add(new HttpHeader("Content-Length", String.valueOf(postData.length())));
        headers.add(new HttpHeader("User-Agent", "Dalvik/1.6.0 (Linux; U; Android 4.3; Nexus 4 Build/JWR66Y)"));
        headers.add(new HttpHeader("Host", "api.wyzecam.com:8443"));
        headers.add(new HttpHeader("Connection", "keep-alive"));
        return NetUtils.readPostContentAsTextFromHttp(context, url, headers, postData, cameraSettings);
    }

    @NonNull
    private static JSONObject composeHead(@NonNull String sv, long ts) {
        JSONObject jsonObject = new JSONObject();
        try {
            jsonObject.put("sc", SC);
            jsonObject.put("sv", sv);
            jsonObject.put("app_ver", APP_VERSION);
            jsonObject.put("ts", ts);
            jsonObject.put(KEY_TOKEN_ACCESS, "");
            jsonObject.put("phone_id", PHONE_ID);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return jsonObject;
    }

    @NonNull
    private static JSONObject systemSetAppInfo() {
        if (DEBUG)
            Log.v(TAG, "systemSetAppInfo()");
        JSONObject jsonObject = composeHead(SV_SET_APP_INFO, System.currentTimeMillis());
        try {
            jsonObject.put("longitude", 0);
            jsonObject.put("latitude", 0);
            jsonObject.put("language", Locale.getDefault().getLanguage().equals("zh") ? "zh-hans" : "en");
            jsonObject.put("phone_model", Build.MODEL.replaceAll(" ", "_") + "_Android_tinycam");
            jsonObject.put("system_type", 2);
            jsonObject.put("system_ver", "Android_" + Build.VERSION.SDK_INT);
            jsonObject.put("android_push_type", 2);
            jsonObject.put(KEY_TOKEN_NOTIFICATION, "ZmFrZXRpbnljYW1rZXk="); // faketinycamkey
//            jsonObject.put(KEY_TOKEN_NOTIFICATION, "fdj+Qw1nC8mBQBqB10mQQlw8YKuZl3IZF6F1qKuX7bU=");
            jsonObject.put("app_num", "4YC155Pe1spGXM7WAGK0NQ=="); // original e1 80 b5 e7 93 de d6 ca 46 5c ce d6 00 62 b4 35
//            jsonObject.put("app_num", "4oG26JTd18tHXc3XAGO1Ng=="); // e2 81 b6 e8 94 dd d7 cb 47 5d cd d7 00 63 b5 36
            jsonObject.put("timezone_city", TimeZone.getDefault().getID());
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return jsonObject;
    }

    @NonNull
    private static JSONObject userLogin(@NonNull String username, @NonNull String password) {
        if (DEBUG)
            Log.v(TAG, "userLogin(username=\"" + username + "\", password=\"" + password + "\")");
        JSONObject jsonObject = composeHead(SV_LOGIN, System.currentTimeMillis());
        try {
            jsonObject.put(KEY_USER_NAME, username);
            jsonObject.put("password", MD5.encode(MD5.encode(password)));
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return jsonObject;
    }

    @NonNull
    private static JSONObject getDeviceList(@NonNull String accessToken) {
        if (DEBUG)
            Log.v(TAG, "getDeviceList(accessToken=\"" + accessToken + "\")");
        JSONObject jsonObject = composeHead(SV_GET_DEVICE_LIST, System.currentTimeMillis());
        try {
            jsonObject.put(KEY_TOKEN_ACCESS, accessToken);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return jsonObject;
    }

    public void setPtzLedCommand(@NonNull PtzListener.Led led) {
        if (DEBUG)
            Log.v(TAG, "setPtzLedCommand(led=" + led + ")");
        MainThread thread = _thread;
        if (thread == null)
            return;
        int channelId = _thread.getChannelId();
        final byte[] b;
        switch (led) {
            case LED_ON:
                b = CamCommand.K10042_setNightVisionStatus(1);
                break;
            case LED_OFF:
                b = CamCommand.K10042_setNightVisionStatus(2);
                break;
            default:
            case LED_AUTO:
                b = CamCommand.K10042_setNightVisionStatus(3);
                break;
        }
        sendData(channelId, b);
    }

    @NonNull
    private static String getAbsoluteUrl(String request) {
        return URL_BASE_OFFICIAL + request;
    }

    private static final String URL_BASE_OFFICIAL = "https://api.wyzecam.com:8443/app/";

//    private static final String URL_ACCEPT_SHARE_DEVICE = "device/accept_share_device";
//    private static final String URL_ACTIVE_SCENE = "scene/active_scene";
//    private static final String URL_CHANGE_PWD = "user/change_password";
//    private static final String URL_CHANGE_USERNAME = "user/change_username";
//    private static final String URL_CHANGE_USERNAME_CODE = "user/send_change_username_code";
//    private static final String URL_CREATE_AUTOMATION = "auto/upload_auto_action";
//    private static final String URL_CREAT_SCENE = "scene/upload_scene_info";
//    private static final String URL_DELETE_ALARM_INFO = "device/delete_alarm_info";
//    private static final String URL_DELETE_AUTOMATION = "auto/delete_auto_action";
//    private static final String URL_DELETE_DEVICE = "device/delete_device";
//    private static final String URL_DELETE_DEVICE_USER = "device/delete_device_user";
//    private static final String URL_DELETE_SCENE = "scene/delete_scene_info";
//    private static final String URL_DELETE_SHARE_INFO = "device/delete_share_info";
//    private static final String URL_EDIT_AUTOMATION = "auto/set_auto_action";
//    private static final String URL_EDIT_SCENE = "scene/set_scene_info";
//    private static final String URL_FORGET_PWD = "user/forget_password";
//    private static final String URL_GET_ALARM_INFO_LIST = "device/get_alarm_info_list";
//    private static final String URL_GET_ALLOW_BINDING_DEVICE_LIST = "system/get_allow_binding_device_list";
//    private static final String URL_GET_AUTOMATION_LIST = "auto/get_auto_action_list";
//    private static final String URL_GET_BINDING_RESULT = "device/get_binding_result";
//    private static final String URL_GET_BINDING_TOKEN = "device/get_binding_token";
//    private static final String URL_GET_DEVICE_ACTION_INFO_LIST = "system/get_device_action_info_list";
//    private static final String URL_GET_DEVICE_CONNECT_INFO_LIST = "device/get_device_connect_info_list";
    private static final String URL_GET_DEVICE_LIST = "device/get_device_list";
//    private static final String URL_GET_DEVICE_USER_LIST = "device/get_device_user_list";
//    private static final String URL_GET_LATEST_FIRM_VER = "getnewst.ashx";
//    private static final String URL_GET_PUSH_INFO = "user/get_push_info";
//    private static final String URL_GET_SCENE_LIST = "scene/get_scene_info_list";
//    private static final String URL_GET_SHARE_INFO_LIST = "device/get_share_info_list";
//    private static final String URL_GET_TOKEN = "user/refresh_token";
//    private static final String URL_GET_USER_INFO = "user/get_user_info";
    private static final String URL_LOGIN = "user/login";
//    private static final String URL_SECURE_CODE = "user/send_security_sms";
    private static final String URL_SET_APP_INFO = "system/set_app_info";
//    private static final String URL_SET_DEVICE_INFO = "device/set_device_info";
//    private static final String URL_SET_PUSH_INFO = "user/set_push_info";
//    private static final String URL_SET_USER_INFO = "user/set_user_info";
//    private static final String URL_SHARE_DEVICE = "device/share_device";
//    private static final String URL_UPLOAD_DEVICE_CONNECT_INFO = "device/upload_device_connect_info";
//    private static final String URL_USER_REGISTER = "user/register";


//    private static final String KEY_DEL_SCENE_GO_HOME = "del_scene_gohome";
//    private static final String KEY_DEL_SCENE_LEAVE_HOME = "del_scene_leavehome";
//    private static final String KEY_DEVICE_ACTION = "device_action";
//    private static final String KEY_ISSUE_FLAG = "issue_flag";
//    private static final String KEY_PHONE_ID = "phone_uuid";
//    private static final String KEY_PROMPT_FIRMWARE_UPDATE = "prompt_firmware_update";
//    private static final String KEY_SHOW_GUIDE_DEVICE_LIST = "show_guide_device_list";
//    private static final String KEY_SHOW_GUIDE_MAIN_ACT = "show_guide_main_act";
//    private static final String KEY_SHOW_GUIDE_PLAYBACK = "show_guide_playback";
//    private static final String KEY_SHOW_GUIDE_RESET_CAMERA = "show_guide_reset_camera";
//    private static final String KEY_SHOW_GUIDE_TIMELAPSE = "show_guide_timelapse";
    private static final String KEY_TOKEN_ACCESS = "access_token";
    private static final String KEY_TOKEN_NOTIFICATION = "push_token";
    private static final String KEY_TOKEN_REFRESH = "refresh_token";
    private static final String KEY_USER_NAME = "user_name";

    private static final String SC = "f5609af3fa9541fd82a486df5fd9965a";
    //    private static final String SC_UPDATE = "f5609af3fa9541fd82a486df5fd9965a";
//    private static final String SV_ACCEPT_SHARE_DEVICE = "acb8fed015954283b584c94d56c976af";
//    private static final String SV_ACTIVE_SCENE = "464156740bba44eeacf7626216d7e94b";
//    private static final String SV_CHANGE_USERNAME = "9bef432296a445f5a3e4135cafafb98d";
//    private static final String SV_CHANGE_USERNAME_CODE = "4ccb2c947dfe4914a97a0f974df5bad4";
//    private static final String SV_CHANGE_USER_PWD = "b9694d6b92e14369b0bfac186ca84058";
//    private static final String SV_CREATE_AUTOMATION = "488686016b404934846e5f898836ba93";
//    private static final String SV_CREATE_SCENE = "d0e3990bc4534cd1b03d654dd08f7a67";
//    private static final String SV_DELETE_ALARM_INFO = "6d4403085fd34fae991fb7c5309b2845";
//    private static final String SV_DELETE_AUTOMATION = "3e57de426c1049baaf03a3b1a6817e82";
//    private static final String SV_DELETE_DEVICE = "12c9f75929c44c968cd47adfdbf4a9ba";
//    private static final String SV_DELETE_DEVICE_USER = "70d51183fc9b4fd487f07388f1c070da";
//    private static final String SV_DELETE_SCENE = "ad9c43cd46034596814754d7446534d0";
//    private static final String SV_DELETE_SHARE_INFO = "6747b3abb82a43bdb49630ad5b153d4b";
//    private static final String SV_EDIT_AUTOMATION = "33418e56f95c4ab4bcb6ae68449135b5";
//    private static final String SV_EDIT_SCENE = "ec6bbfef404b4c33b6e7212667315b62";
//    private static final String SV_FORGET_PWD = "c8077f1e1fe5447bbf33b5cd22dacbbc";
//    private static final String SV_GET_ALARM_INFO_LIST = "eafeef213f764f9486fcf36a75e4a9fc";
//    private static final String SV_GET_ALLOW_BINDING_DEVICE_LIST = "fc41abc854844364bcab692f76e581fd";
//    private static final String SV_GET_AUTOMATION_LIST = "46d88bb23b724ba9978a8f5476140143";
//    private static final String SV_GET_BINDING_RESULT = "80102f4ae1ec47f1b935720e56f7ef05";
//    private static final String SV_GET_BINDING_TOKEN = "e1c9fa09f12a486192f350511f77e868";
//    private static final String SV_GET_DEVICE_ACTION_INFO_LIST = "bd50f4e96acf46a2840b9611e00a2be2";
//    private static final String SV_GET_DEVICE_CONNECT_INFO = "75f0e2a02f394d4c9a3a14911768030e";
    private static final String SV_GET_DEVICE_LIST = "527f57974f7b4cea9810b90a66b42b6c";
//    private static final String SV_GET_DEVICE_USER_LIST = "196ed096d2dd4064937d95d9aec32157";
//    private static final String SV_GET_PUSH_INFO = "463c627144fb4288b04047f1aad2f46c";
//    private static final String SV_GET_SCENE_LIST = "bc885febd79046ad924705abab1055cc";
//    private static final String SV_GET_SHARE_INFO_LIST = "2bb33df213844753afe957fa6b10a134";
//    private static final String SV_GET_TOKEN = "66266e1c6b1044a7b8538f703f572a32";
//    private static final String SV_GET_USER_INFO = "a318b93c4c9546e4a6d78d1a93d8dcab";
    private static final String SV_LOGIN = "1ee66ee1fe03403b9ded3fe2fa869f2a";
//    private static final String SV_SECURE_CODE = "7dfd646117174e2f80e5516d7e31876c";
    private static final String SV_SET_APP_INFO = "32916d2b3e29448fa8926fae4af9857b";
//    private static final String SV_SET_DEVICE_INFO = "8df8909f4a2749e08fd0e907d3126a7d";
//    private static final String SV_SET_PUSH_INFO = "d0dbd113f3164230a528b3ca7f9f8aaa";
//    private static final String SV_SET_USER_INFO = "ca15028b44e24d9da571e98a18a5b7b1";
//    private static final String SV_SHARE_DEVICE = "2254bd8b55bb4f7c96fd41edbc6b5b37";
//    private static final String SV_UPDATE_LATEST = "af7849e9ebf14ab49cdc3b47f658039d";
//    private static final String SV_UPLOAD_DEVICE_CONNECT_INFO = "e46ea54ae59740ea8847918c163a3768";
//    private static final String SV_USER_REGISTER = "65157358ed3c463988d2dde35eaa770a";

}


class MD5 {
    static String encode(String str) {
        try {
            int i;
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            char[] charArray = str.toCharArray();
            byte[] byteArray = new byte[charArray.length];
            for (i = 0; i < charArray.length; i++) {
                byteArray[i] = (byte) charArray[i];
            }
            byte[] md5Bytes = md5.digest(byteArray);
            StringBuilder hexValue = new StringBuilder();
            for (byte b : md5Bytes) {
                int val = b & 255;
                if (val < 16) {
                    hexValue.append("0");
                }
                hexValue.append(Integer.toHexString(val));
            }
            return hexValue.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }
}

class CamProtocolUtils {
    private static final byte[] head = new byte[]{(byte) 72, (byte) 76};
//    static final int headLength = 16;
//    private static final short version = (short) 1;
    private int code;
    private byte[] data;
    private int dataLength = 0;

    private CamProtocolUtils(int code, int dataLength, byte[] data) {
        this.code = code;
        this.dataLength = dataLength;
        this.data = data;
    }

//    public byte[] toBytes() {
//        byte[] protocol = new byte[((this.dataLength <= 0 ? 0 : this.dataLength) + 16)];
//        ByteOperator.byteArrayCopy(protocol, 0, head, 0, 1);
//        ByteOperator.byteArrayCopy(protocol, 2, ByteOperator.int16ToByteArray(1), 0, 1);
//        ByteOperator.byteArrayCopy(protocol, 4, ByteOperator.int16ToByteArray(this.code), 0, 1);
//        if (this.data != null && this.dataLength > 0) {
//            ByteOperator.byteArrayCopy(protocol, 6, ByteOperator.int16ToByteArray(this.data.length), 0, 1);
//            ByteOperator.byteArrayCopy(protocol, 16, this.data, 0, this.dataLength - 1);
//        }
//        return protocol;
//    }

    static byte[] create(int code, int dataLength, byte[] data) {
        int i;
        if (dataLength <= 0) {
            i = 0;
        } else {
            i = dataLength;
        }
        byte[] protocol = new byte[(i + 16)];
        ByteOperator.byteArrayCopy(protocol, 0, head, 0, 1);
        ByteOperator.byteArrayCopy(protocol, 2, ByteOperator.int16ToByteArray(1), 0, 1);
        ByteOperator.byteArrayCopy(protocol, 4, ByteOperator.int16ToByteArray(code), 0, 1);
        if (data != null && dataLength > 0) {
            ByteOperator.byteArrayCopy(protocol, 6, ByteOperator.int16ToByteArray(data.length), 0, 1);
            ByteOperator.byteArrayCopy(protocol, 16, data, 0, dataLength - 1);
        }
        return protocol;
    }

    private static int checkData(byte[] data, boolean isOnlyCheckHead) {
        if (data.length < 16) {
            return -1;
        }
        if (data[0] != (byte) 72 || data[1] != (byte) 76) {
            return -2;
        }
        int textLength = ByteOperator.byteArray2int(data, 6);
        return (isOnlyCheckHead || textLength + 16 <= data.length) ? textLength : -3;
    }

    static CamProtocolUtils getFromBytes(byte[] data) {
        int dataLength = checkData(data, false);
        if (dataLength >= 0) {
            return new CamProtocolUtils(ByteOperator.byteArray2int(data, 4), dataLength, ByteOperator.byteArrayCut(data, 16, dataLength + 15));
        }
        return null;
    }

    int getCode() {
        return this.code;
    }

    int getDataLength() {
        return this.dataLength;
    }

    byte[] getData() {
        return this.data;
    }
}

final class ByteOperator {
//    private static String TAG = "ByteOperator ";

//    static int byteArray2int(byte[] byteArray) throws StringIndexOutOfBoundsException {
//        return (byteArray[0] & 255) | ((byteArray[1] << 8) & 0xFF00);
//    }

    static int byteArray2int(byte[] byteArray, int startPosition) throws StringIndexOutOfBoundsException {
        return (byteArray[startPosition] & 255) | ((byteArray[startPosition + 1] << 8) & 0xFF00);
    }

//    static int byteArray4intL(byte[] byteArray) throws StringIndexOutOfBoundsException {
//        return (((byteArray[0] & 255) | ((byteArray[1] << 8) & 0xFF00)) | ((byteArray[2] << 16) & 16711680)) | ((byteArray[3] << 24) & -16777216);
//    }

//    static int byteArray4intL(byte[] byteArray, int strPosition) throws StringIndexOutOfBoundsException {
//        return (((byteArray[strPosition] & 255) | ((byteArray[strPosition + 1] << 8) & 0xFF00)) | ((byteArray[strPosition + 2] << 16) & 16711680)) | ((byteArray[strPosition + 3] << 24) & -16777216);
//    }

//    static int byteArray4intH(byte[] byteArray) throws StringIndexOutOfBoundsException {
//        int num = byteArray[3] & 255;
//        Log.i(TAG + ":byteArray4intH", num + ":" + Integer.toBinaryString(num));
//        num |= (byteArray[2] << 8) & 0xFF00;
//        Log.i(TAG + ":byteArray4intH", num + ":" + Integer.toBinaryString(num));
//        num |= (byteArray[1] << 16) & 16711680;
//        Log.i(TAG + ":byteArray4intH", num + ":" + Integer.toBinaryString(num));
//        num |= (byteArray[0] << 24) & -16777216;
//        Log.i(TAG + ":byteArray4intH", num + ":" + Integer.toBinaryString(num));
//        return num;
//    }

//    static int byteArray4intH(byte[] byteArray, int strPosition) throws StringIndexOutOfBoundsException {
//        int num = byteArray[strPosition + 3] & 255;
//        Log.i(TAG + ":byteArray4intH", num + ":" + Integer.toBinaryString(num));
//        num |= (byteArray[strPosition + 2] << 8) & 0xFF00;
//        Log.i(TAG + ":byteArray4intH", num + ":" + Integer.toBinaryString(num));
//        num |= (byteArray[strPosition + 1] << 16) & 16711680;
//        Log.i(TAG + ":byteArray4intH", num + ":" + Integer.toBinaryString(num));
//        num |= (byteArray[strPosition] << 24) & -16777216;
//        Log.i(TAG + ":byteArray4intH", num + ":" + Integer.toBinaryString(num));
//        return num;
//    }

//    static int byteArray4int(byte[] byteArray, int strPosition) throws StringIndexOutOfBoundsException {
//        return (((byteArray[strPosition] & 255) | ((byteArray[strPosition + 1] << 8) & 0xFF00)) | ((byteArray[strPosition + 2] << 16) & 16711680)) | ((byteArray[strPosition + 3] << 24) & -16777216);
//    }

//    static byte[] intToByteArray(int num) {
//        return new byte[]{(byte) (num & 255), (byte) ((0xFF00 & num) >> 8), (byte) ((16711680 & num) >> 16), (byte) ((-16777216 & num) >> 24)};
//    }

//    static byte[] intTobyteArray2(int num) {
//        return new byte[]{(byte) (num & 255), (byte) ((0xFF00 & num) >> 8)};
//    }

//    static byte[] intTobyteArrayH(int num) {
//        return new byte[]{(byte) (num & 255), (byte) ((0xFF00 & num) >> 8), (byte) ((16711680 & num) >> 16), (byte) ((-16777216 & num) >> 24)};
//    }

//    static boolean byteArrayCopy(byte[] dstArray, byte[] srcArray) throws StringIndexOutOfBoundsException {
//        int dstLen = dstArray.length;
//        int srcLen = srcArray.length;
//        if (dstLen < srcLen) {
//            srcLen = dstLen;
//        }
//        System.arraycopy(srcArray, 0, dstArray, 0, srcLen);
//        return true;
//    }

    static void byteArrayCopy(byte[] dstArray, int dstStartPosition, byte[] srcArray, int srcStartposition, int srcEndPosition) throws StringIndexOutOfBoundsException {
        int dstLen = dstArray.length - dstStartPosition;
        int srcLen = (srcEndPosition - srcStartposition) + 1;
        if (dstLen < srcLen) {
            srcLen = dstLen;
        }
        System.arraycopy(srcArray, srcStartposition, dstArray, dstStartPosition, srcLen);
    }

//    static String byteArrayToHexString(byte[] byteArray, int length) throws StringIndexOutOfBoundsException {
//        int lengthLimit;
//        String hexString = "";
//        if (length > byteArray.length) {
//            lengthLimit = byteArray.length;
//        } else {
//            lengthLimit = length;
//        }
//        for (int i = 0; i < lengthLimit; i++) {
//            String hex = Integer.toHexString(byteArray[i] & 255);
//            if (hex.length() == 1) {
//                hex = '0' + hex;
//            }
//            hexString = hexString + hex.toUpperCase(Locale.ENGLISH);
//        }
//        return hexString;
//    }

//    static String byteArrayToHexString(byte[] byteArray) {
//        String hexString = "";
//        int length = byteArray == null ? 0 : byteArray.length;
//        for (int i = 0; i < length; i++) {
//            String hex = Integer.toHexString(byteArray[i] & 255);
//            if (hex.length() == 1) {
//                hex = '0' + hex;
//            }
//            hexString = hexString + hex.toUpperCase(Locale.ENGLISH);
//        }
//        return hexString;
//    }

//    static String byteArrayToHexString(byte[] byteArray, int startPst, int endPst) throws StringIndexOutOfBoundsException {
//        String hexString = "";
//        for (int i = startPst; i <= endPst; i++) {
//            String hex = Integer.toHexString(byteArray[i] & 255);
//            if (hex.length() == 1) {
//                hex = '0' + hex;
//            }
//            hexString = hexString + hex.toUpperCase(Locale.ENGLISH);
//        }
//        return hexString;
//    }

//    static String byteArrayToAscllString(byte[] byteArray) {
//        String AscllString = "";
//        int length = byteArray == null ? 0 : byteArray.length;
//        for (int i = 0; i < length; i++) {
//            AscllString = AscllString + ((char) (byteArray[i] & 255));
//        }
//        return AscllString;
//    }

    static byte[] byteArrayCut(byte[] srcArray, int startPst, int endPst) throws StringIndexOutOfBoundsException {
        if (endPst < startPst) {
            return new byte[48];
        }
        if (endPst == startPst) {
            return new byte[]{srcArray[startPst]};
        }
        byte[] dstArray = new byte[((endPst - startPst) + 1)];
        System.arraycopy(srcArray, startPst, dstArray, 0, dstArray.length);
        return dstArray;
    }

//    static boolean byteArrayCompare(byte[] dstArray, int dstStartPosition, byte[] srcArray, int srcStartPosition, int srcEndPosition) throws StringIndexOutOfBoundsException {
//        int srcLen = (srcEndPosition - srcStartPosition) + 1;
//        if (dstArray.length - dstStartPosition < srcLen) {
//            return false;
//        }
//        byte[] srcA = byteArrayCut(srcArray, srcStartPosition, srcEndPosition);
//        byte[] dstA = byteArrayCut(dstArray, dstStartPosition, srcLen - 1);
//        return byteArrayToHexString(srcA, srcA.length).equals(byteArrayToHexString(dstA, dstA.length));
//    }

//    static String byteArrayToString(byte[] byteArray) {
//        int len = byteArray.length;
//        byte[] bytes = new byte[len];
//        for (int i = 0; i < len; i++) {
//            bytes[i] = Byte.valueOf(byteArray[i]).byteValue();
//        }
//        return new String(bytes);
//    }

//    static int[] byteArrayToInt9126(byte[] byteArray) {
//        int[] timeToRecordInfo = new int[15];
//        for (int i = 0; i < timeToRecordInfo.length - 1; i++) {
//            timeToRecordInfo[i] = byteArray[i + 4];
//        }
//        timeToRecordInfo[13] = byteArray2int(new byte[]{byteArray[17], byteArray[18]});
//        timeToRecordInfo[14] = byteArray4intH(new byte[]{byteArray[19], byteArray[20], byteArray[21], byteArray[22]});
//        return timeToRecordInfo;
//    }

//    static String[] byteArrayToString9002(byte[] byteArray) {
//        String[] sambaInfo = new String[8];
//        int ipLength = byteArray[4];
//        int savePathLengthPosition = (4 + ipLength) + 1;
//        int savePathLength = byteArray[savePathLengthPosition];
//        int userNameLengthPosition = (savePathLengthPosition + savePathLength) + 1;
//        int userNameLength = byteArray[userNameLengthPosition];
//        int passWorkLengthPosition = (userNameLengthPosition + userNameLength) + 1;
//        int passWordLength = byteArray[passWorkLengthPosition];
//        int workGroupLengthPosition = (passWorkLengthPosition + passWordLength) + 1;
//        int workGroupLength = byteArray[workGroupLengthPosition];
//        int sambaNameLengthPosition = (workGroupLengthPosition + workGroupLength) + 1;
//        int sambaNameLength = byteArray[sambaNameLengthPosition];
//        int sambaSSIDLengthPosition = (sambaNameLengthPosition + sambaNameLength) + 1;
//        int sambaSSIDLength = byteArray[sambaSSIDLengthPosition];
//        int sambaShareLengthPosition = (sambaSSIDLengthPosition + sambaSSIDLength) + 1;
//        int sambaShareNameLength = byteArray[sambaShareLengthPosition];
//        sambaInfo[0] = byteArrayToString(byteArray, 5, 4 + ipLength);
//        sambaInfo[1] = byteArrayToString(byteArray, savePathLengthPosition + 1, savePathLengthPosition + savePathLength);
//        sambaInfo[2] = byteArrayToString(byteArray, userNameLengthPosition + 1, userNameLengthPosition + userNameLength);
//        sambaInfo[3] = byteArrayToString(byteArray, passWorkLengthPosition + 1, passWorkLengthPosition + passWordLength);
//        sambaInfo[4] = byteArrayToString(byteArray, workGroupLengthPosition + 1, workGroupLengthPosition + workGroupLength);
//        sambaInfo[5] = byteArrayToString(byteArray, sambaNameLengthPosition + 1, sambaNameLengthPosition + sambaNameLength);
//        sambaInfo[6] = byteArrayToString(byteArray, sambaSSIDLengthPosition + 1, sambaSSIDLengthPosition + sambaSSIDLength);
//        sambaInfo[7] = byteArrayToString(byteArray, sambaShareLengthPosition + 1, sambaShareLengthPosition + sambaShareNameLength);
//        Log.i(TAG, "ipLengthPosition" + 4 + "  ipLength" + ipLength + "        byteArrayLenth" + byteArray.length + "  sambaInfo[0] " + sambaInfo[0] + "  sambaInfo[1] " + sambaInfo[1] + "  sambaInfo[2] " + sambaInfo[2] + "  sambaInfo[3] " + sambaInfo[3] + "  sambaInfo[4] " + sambaInfo[4] + "  sambaInfo[5] " + sambaInfo[5] + "  sambaInfo[6] " + sambaInfo[6] + "  sambaInfo[7] " + sambaInfo[7]);
//        return sambaInfo;
//    }

//    static String byteArrayToString(byte[] byteArray, int startPosition, int endPosition) throws StringIndexOutOfBoundsException {
//        byte[] bytes = new byte[((endPosition - startPosition) + 1)];
//        for (int i = startPosition; i <= endPosition; i++) {
//            bytes[i - startPosition] = Byte.valueOf(byteArray[i]).byteValue();
//        }
//        return new String(bytes);
//    }

//    static boolean bytesEquals(byte[] src, byte[] dst) {
//        if (src.length != dst.length) {
//            return false;
//        }
//        for (int i = 0; i < dst.length; i++) {
//            if (src[i] != dst[i]) {
//                return false;
//            }
//        }
//        return true;
//    }

//    static String byteArrayToUrlcode(byte[] byteArray, boolean flag) throws UnsupportedEncodingException {
//        String base64String = "";
//        String urlString = "";
//        if (byteArray == null) {
//            return "";
//        }
//        base64String = Base64.encodeToString(byteArray, 2);
//        try {
//            urlString = URLEncoder.encode(base64String, "UTF-8");
//        } catch (UnsupportedEncodingException e) {
//            Log.i(TAG + ":byteArrayToUrlcode", "Exception = " + e.getMessage());
//            e.printStackTrace();
//        }
//        Log.i(TAG + ":byteArrayToUrlcode", "byte operator Y :base64 string = " + base64String);
//        if (flag && urlString.endsWith("%0A")) {
//            Log.i(TAG + ":byteArrayToUrlcode", "byte operator Y :url string = " + urlString.replace("%0A", ""));
//            return urlString.replace("%0A", "");
//        }
//        Log.i(TAG + ":byteArrayToUrlcode", "byte operator  :url string = " + urlString);
//        return urlString;
//    }

//    static String byteArrayToBase64(byte[] byteArray) {
//        if (byteArray == null) {
//            return "";
//        }
//        return Base64.encodeToString(byteArray, 2);
//    }

    static byte[] reverseByteArray(byte[] data) {
        byte[] result = new byte[16];
        for (int i = 0; i < 4; i++) {
            result[i] = data[3 - i];
            result[i + 4] = data[7 - i];
            result[i + 8] = data[11 - i];
            result[i + 12] = data[15 - i];
        }
        return result;
    }

//    static byte[] get4BytesArray(String str) {
//        byte[] byteArray = new byte[]{(byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0};
//        byte[] src = str.getBytes();
//        int length = src.length;
//        if (length > 16) {
//            length = 16;
//        }
//        System.arraycopy(src, 0, byteArray, 0, length);
//        return byteArray;
//    }

//    static byte[] hexStringToBytes(String hexString) {
//        if (hexString == null || hexString.equals("")) {
//            return null;
//        }
//        hexString = hexString.toUpperCase(Locale.ENGLISH);
//        int length = hexString.length() / 2;
//        char[] hexChars = hexString.toCharArray();
//        byte[] d = new byte[length];
//        for (int i = 0; i < length; i++) {
//            int pos = i * 2;
//            d[i] = (byte) ((charToByte(hexChars[pos]) << 4) | charToByte(hexChars[pos + 1]));
//        }
//        return d;
//    }

//    private static byte charToByte(char c) {
//        return (byte) "0123456789ABCDEF".indexOf(c);
//    }

    static byte[] int16ToByteArray(int num) {
        return new byte[]{(byte) (num & 255), (byte) ((0xFF00 & num) >> 8)};
    }

//    static byte[] int16ToByteArrayH(int num) {
//        return new byte[]{(byte) (num & 255), (byte) ((0xFF00 & num) >> 8)};
//    }

//    static short byteArrayToShort(byte[] b, int index) throws StringIndexOutOfBoundsException {
//        return (short) ((b[index + 1] << 8) | (b[index] & 255));
//    }

//    static char byteArrayToChar(byte[] b, int index) throws StringIndexOutOfBoundsException {
//        return (char) (b[index] & 255);
//    }

//    static byte[] shortToByteArray(short s) {
//        return new byte[]{(byte) ((s >>> 8) & 255), (byte) (s & 255)};
//    }

//    static boolean byteArrayCopyLittleEnding(byte[] dstArray, int dstStartPosition, byte[] srcArray, int srcStartposition, int srcEndPosition) throws StringIndexOutOfBoundsException {
//        int srcLen = (srcEndPosition - srcStartposition) + 1;
//        if (dstArray.length - dstStartPosition < srcLen) {
//            return false;
//        }
//        for (int i = 0; i < srcLen; i++) {
//            dstArray[i + dstStartPosition] = srcArray[srcEndPosition - i];
//        }
//        return true;
//    }

//    static byte[] stringIPToLittleEndianByteArray(String ip) {
//        String[] serverIPArray = null;
//        if (!ip.equals("") && ip.contains(".")) {
//            serverIPArray = ip.split("\\.");
//        }
//        byte[] data = new byte[4];
//        if (serverIPArray.length == 4) {
//            data[3] = (byte) Integer.valueOf(serverIPArray[0]).intValue();
//            data[2] = (byte) Integer.valueOf(serverIPArray[1]).intValue();
//            data[1] = (byte) Integer.valueOf(serverIPArray[2]).intValue();
//            data[0] = (byte) Integer.valueOf(serverIPArray[3]).intValue();
//        } else {
//            Log.e(TAG, "stringIPToLittleEndianByteArray format error : " + ip);
//        }
//        return data;
//    }
}

class CamCommand {
//    static final int PARAM_BIT_RATE = 3;
//    static final int PARAM_CO_ALARM = 18;
//    static final int PARAM_FLIP_HOR = 6;
//    static final int PARAM_FLIP_VER = 7;
//    static final int PARAM_FRAME_RATE = 5;
//    static final int PARAM_LOG_SD = 9;
//    static final int PARAM_LOG_UD = 10;
//    static final int PARAM_MOTION_ALARM = 13;
//    static final int PARAM_MOTION_LEVEL = 14;
//    static final int PARAM_NETWORK_LIGHT = 1;
//    static final int PARAM_NIGHT_VISION = 2;
//    static final int PARAM_OSD = 8;
//    static final int PARAM_RECORD = 12;
//    static final int PARAM_RESOLUTION = 4;
//    static final int PARAM_SMOKE_ALARM = 17;
//    static final int PARAM_SOUND_ALARM = 15;
//    static final int PARAM_SOUND_LEVEL = 16;
//    static final int PARAM_TELNET = 11;
//    static final int[] defaultParamKeyList = new int[] {
//            PARAM_NETWORK_LIGHT,
//            PARAM_NIGHT_VISION,
//            PARAM_BIT_RATE,
//            PARAM_RESOLUTION,
//            PARAM_FRAME_RATE,
//            PARAM_FLIP_HOR,
//            PARAM_FLIP_VER,
//            PARAM_OSD,
//            PARAM_LOG_SD,
//            PARAM_LOG_UD,
//            PARAM_TELNET,
//            PARAM_RECORD,
//            PARAM_MOTION_ALARM,
//            PARAM_MOTION_LEVEL,
//            PARAM_SOUND_ALARM,
//            PARAM_SOUND_LEVEL,
//            PARAM_SMOKE_ALARM,
//            PARAM_CO_ALARM};

    static byte[] K10000_connectRequest() {
        if (ProtocolWyzecam.DEBUG)
            Log.v(ProtocolWyzecam.TAG, "K10000_connectRequest()");
        return CamProtocolUtils.create(10000, 0, null);
    }

    static byte[] K10002_connectAuth(@NonNull byte[] r2, String username, boolean isOpenVideoChannel, boolean isOpenAudioChannel) {
        if (ProtocolWyzecam.DEBUG)
            Log.v(ProtocolWyzecam.TAG, "K10002_connectAuth(username=\"" + username + "\")");
        byte b = (byte) 1;
        if (r2.length != 16) {
            Log.d("K10002_connectAuth", "r2 is null");
            return null;
        }
        byte b2;
        byte[] data = new byte[22];
        if (username.length() < 4) {
            username = username + "1234";
        }
        ByteOperator.byteArrayCopy(data, 0, r2, 0, 15);
        ByteOperator.byteArrayCopy(data, 16, username.getBytes(), 0, 3);
        if (isOpenVideoChannel) {
            b2 = (byte) 1;
        } else {
            b2 = (byte) 0;
        }
        data[20] = b2;
        if (!isOpenAudioChannel) {
            b = (byte) 0;
        }
        data[21] = b;
        return CamProtocolUtils.create(10002, data.length, data);
    }

//    static byte[] K10010_channelControl(int channel, boolean isOpen) {
//        byte[] bArr = new byte[2];
//        bArr[0] = (byte) channel;
//        bArr[1] = isOpen ? (byte) 1 : (byte) 2;
//        return CamProtocolUtils.create(10010, 2, bArr);
//    }

//    static byte[] K10020_getParam(int[] paramKeyList) {
//        byte[] data = new byte[(paramKeyList.length + 1)];
//        data[0] = (byte) paramKeyList.length;
//        for (int i = 1; i <= paramKeyList.length; i++) {
//            data[i] = (byte) paramKeyList[i - 1];
//        }
//        return CamProtocolUtils.create(10020, data.length, data);
//    }

//    static byte[] K10020_getAllParam() {
//        return K10020_getParam(defaultParamKeyList);
//    }

//    static byte[] K10023_getBasicInfo() {
//        return CamProtocolUtils.create(10023, 0, null);
//    }

//    static byte[] K10030_getNetworkLightStatus() {
//        return CamProtocolUtils.create(10030, 0, null);
//    }

//    static byte[] K10032_setNetworkLightStatus(int status) {
//        return CamProtocolUtils.create(10032, 1, new byte[]{(byte) status});
//    }

//    static byte[] K10040_getNightVisionStatus() {
//        return CamProtocolUtils.create(10040, 0, null);
//    }

    // status: 1..3
    static byte[] K10042_setNightVisionStatus(int status) {
        return CamProtocolUtils.create(10042, 1, new byte[]{(byte) status});
    }

//    static byte[] K10050_getVideoParam() {
//        return CamProtocolUtils.create(10050, 0, null);
//    }

//    static byte[] K10052_setVideoParam(int bitRate, int resolution, int fps, int horFlip, int verFlip) {
//        byte[] data = new byte[]{(byte) 0, (byte) 0, (byte) resolution, (byte) fps, (byte) horFlip, (byte) verFlip};
//        ByteOperator.byteArrayCopy(data, 0, ByteOperator.intTobyteArray2(bitRate), 0, 1);
//        return CamProtocolUtils.create(10052, data.length, data);
//    }

//    static byte[] K10060_getAPEncrpytStatus() {
//        return CamProtocolUtils.create(10060, 0, null);
//    }

//    static byte[] K10062_setAPPwd(String pwd) {
//        byte[] data = new byte[(pwd.length() + 2)];
//        data[0] = (byte) 1;
//        data[1] = (byte) pwd.length();
//        ByteOperator.byteArrayCopy(data, 2, pwd.getBytes(), 0, pwd.length() - 1);
//        return CamProtocolUtils.create(10062, data.length, data);
//    }

//    static byte[] K10064_toEncryptAPMode() {
//        return CamProtocolUtils.create(10064, 0, null);
//    }

//    static byte[] K10070_getOSDStatus() {
//        return CamProtocolUtils.create(10070, 0, null);
//    }

//    static byte[] K10072_setCameraOSDDisplay(boolean isDisplay) {
//        byte[] bArr = new byte[1];
//        bArr[0] = (byte) (isDisplay ? 1 : 2);
//        return CamProtocolUtils.create(10072, 1, bArr);
//    }

//    static byte[] K10080_getCameraLogStorage() {
//        return CamProtocolUtils.create(10080, 0, null);
//    }

//    static byte[] K10082_setCameraLogStorage(boolean isSDOn, boolean isUDOn) {
//        byte[] bArr = new byte[2];
//        bArr[0] = (byte) (isSDOn ? 1 : 2);
//        bArr[1] = (byte) (isUDOn ? 1 : 2);
//        return CamProtocolUtils.create(10082, 2, bArr);
//    }

//    static byte[] K10092_setCameraTime(long timestamp) {
//        return CamProtocolUtils.create(10092, 4, ByteOperator.intToByteArray((int) timestamp));
//    }

//    static byte[] K10120_getManualRecordStatus() {
//        return CamProtocolUtils.create(10120, 0, null);
//    }

//    static byte[] K10122_setManualRecordStatus(boolean isStart, int startTimeInSec) {
//        byte[] data = new byte[5];
//        data[0] = isStart ? (byte) 1 : (byte) 2;
//        ByteOperator.byteArrayCopy(data, 1, ByteOperator.intToByteArray(startTimeInSec), 0, 3);
//        return CamProtocolUtils.create(10122, data.length, data);
//    }

//    static byte[] K10130_getTimeLapseStatus() {
//        return CamProtocolUtils.create(10130, 0, null);
//    }

//    static byte[] K10132_setTimeLapseTask(byte[] task) {
//        return CamProtocolUtils.create(10132, task.length, task);
//    }

//    static byte[] K10140_getVideoClipList(int startTimeInSec, int endTimeInSec) {
//        byte[] data = new byte[8];
//        ByteOperator.byteArrayCopy(data, 0, ByteOperator.intToByteArray(startTimeInSec), 0, 3);
//        ByteOperator.byteArrayCopy(data, 4, ByteOperator.intToByteArray(endTimeInSec), 0, 3);
//        return CamProtocolUtils.create(10140, data.length, data);
//    }

//    static byte[] K10142_deleteVideoClip(byte[] list) {
//        byte[] data = new byte[(list.length + 4)];
//        ByteOperator.byteArrayCopy(data, 0, ByteOperator.intToByteArray(list.length), 0, 3);
//        return CamProtocolUtils.create(10142, data.length, data);
//    }

//    static byte[] K10150_replay(boolean isReplay, int type, int startTimeInSec) {
//        byte b;
//        byte[] data = new byte[6];
//        if (isReplay) {
//            b = (byte) 1;
//        } else {
//            b = (byte) 2;
//        }
//        data[0] = b;
//        data[1] = (byte) type;
//        ByteOperator.byteArrayCopy(data, 2, ByteOperator.intToByteArray(startTimeInSec), 0, 3);
//        return CamProtocolUtils.create(10150, data.length, data);
//    }

//    static byte[] K10160_getSambaParam() {
//        return CamProtocolUtils.create(10160, 0, null);
//    }

//    static byte[] K10162_setSambaParam(String ip, String path, String un, String pwd, String workGroup, String deviceName, String shareName) {
//        byte[] data = new byte[(((((((ip.length() + 7) + path.length()) + un.length()) + pwd.length()) + workGroup.length()) + deviceName.length()) + shareName.length())];
//        int index = 0 + 1;
//        data[0] = (byte) ip.length();
//        ByteOperator.byteArrayCopy(data, index, ip.getBytes(), 0, ip.length() - 1);
//        int length = ip.length() + 1;
//        index = length + 1;
//        data[length] = (byte) path.length();
//        ByteOperator.byteArrayCopy(data, index, path.getBytes(), 0, path.length() - 1);
//        length = index + path.length();
//        index = length + 1;
//        data[length] = (byte) un.length();
//        ByteOperator.byteArrayCopy(data, index, un.getBytes(), 0, un.length() - 1);
//        length = index + un.length();
//        index = length + 1;
//        data[length] = (byte) pwd.length();
//        ByteOperator.byteArrayCopy(data, index, pwd.getBytes(), 0, pwd.length() - 1);
//        length = index + pwd.length();
//        index = length + 1;
//        data[length] = (byte) workGroup.length();
//        ByteOperator.byteArrayCopy(data, index, workGroup.getBytes(), 0, workGroup.length() - 1);
//        length = index + workGroup.length();
//        index = length + 1;
//        data[length] = (byte) deviceName.length();
//        ByteOperator.byteArrayCopy(data, index, deviceName.getBytes(), 0, deviceName.length() - 1);
//        length = index + deviceName.length();
//        index = length + 1;
//        data[length] = (byte) shareName.length();
//        ByteOperator.byteArrayCopy(data, index, shareName.getBytes(), 0, shareName.length() - 1);
//        return CamProtocolUtils.create(10162, data.length, data);
//    }

//    static byte[] K10164_getSambaStorageType() {
//        return CamProtocolUtils.create(10164, 0, null);
//    }

//    static byte[] K10166_setTimeLapseTask(int type) {
//        return CamProtocolUtils.create(10166, 1, new byte[]{(byte) type});
//    }

//    static byte[] K10168_getSambaStatus() {
//        return CamProtocolUtils.create(10168, 0, null);
//    }

//    static byte[] K10170_setSambaStatus(boolean isEnable) {
//        byte[] bArr = new byte[1];
//        bArr[0] = isEnable ? (byte) 1 : (byte) 2;
//        return CamProtocolUtils.create(10170, 1, bArr);
//    }

//    static byte[] K10172_delCamSamba() {
//        return CamProtocolUtils.create(10172, 0, null);
//    }

//    static byte[] K10174_getCamSambaConnectStatus() {
//        return CamProtocolUtils.create(10174, 0, null);
//    }

//    static byte[] K10176_getSambaStorageTime() {
//        return CamProtocolUtils.create(10176, 0, null);
//    }

//    static byte[] K10178_setSambaStorageTime(int[] timeList) {
//        return CamProtocolUtils.create(10178, 4, new byte[]{(byte) timeList[0], (byte) timeList[1], (byte) timeList[2], (byte) timeList[3]});
//    }

//    static byte[] K10190_getRecordType() {
//        return CamProtocolUtils.create(10190, 0, null);
//    }

//    static byte[] K10192_setRecordType(int type) {
//        return CamProtocolUtils.create(10192, 1, new byte[]{(byte) type});
//    }

//    static byte[] K10200_getMotionAlarmParam() {
//        return CamProtocolUtils.create(10200, 0, null);
//    }

//    static byte[] K10202_setMotionAlarmParam(boolean isEnable, int level) {
//        byte[] bArr = new byte[2];
//        bArr[0] = isEnable ? (byte) 1 : (byte) 2;
//        bArr[1] = (byte) level;
//        return CamProtocolUtils.create(10202, 2, bArr);
//    }

//    static byte[] K10220_update(String checkCode, String url) {
//        byte[] data = new byte[((checkCode.length() + url.length()) + 2)];
//        data[0] = (byte) checkCode.length();
//        ByteOperator.byteArrayCopy(data, 1, checkCode.getBytes(), 0, checkCode.length() - 1);
//        data[checkCode.length() + 1] = (byte) url.length();
//        ByteOperator.byteArrayCopy(data, checkCode.length() + 2, url.getBytes(), 0, url.length() - 1);
//        return CamProtocolUtils.create(10220, data.length, data);
//    }

//    static byte[] K10230_getRecordInfoInHours(int startTimeStampInSec) {
//        return CamProtocolUtils.create(10230, 4, ByteOperator.intToByteArray(startTimeStampInSec));
//    }

//    static byte[] K10232_getRecordInfoInMinutes(int startTimeStampInSec) {
//        return CamProtocolUtils.create(10232, 4, ByteOperator.intToByteArray(startTimeStampInSec));
//    }

//    static byte[] K10240_getSDCardInfo() {
//        return CamProtocolUtils.create(10240, 0, null);
//    }

//    static byte[] K10242_formatSDCard() {
//        return CamProtocolUtils.create(10242, 0, null);
//    }

//    static byte[] K10250_getSoundAlarmInfo() {
//        return CamProtocolUtils.create(10250, 0, null);
//    }

//    static byte[] K10252_setSoundAlarm(int isEnable, int sensitivity) {
//        return CamProtocolUtils.create(10252, 2, new byte[]{(byte) isEnable, (byte) sensitivity});
//    }

//    static byte[] K10260_getSmokeAlarmInfo() {
//        return CamProtocolUtils.create(10260, 0, null);
//    }

//    static byte[] K10262_setSmokeAlarm(boolean isEnable) {
//        byte[] bArr = new byte[1];
//        bArr[0] = isEnable ? (byte) 1 : (byte) 2;
//        return CamProtocolUtils.create(10262, 1, bArr);
//    }

//    static byte[] K10270_getCOAlarmInfo() {
//        return CamProtocolUtils.create(10270, 0, null);
//    }

//    static byte[] K10272_setCOAlarm(boolean isEnable) {
//        byte[] bArr = new byte[1];
//        bArr[0] = isEnable ? (byte) 1 : (byte) 2;
//        return CamProtocolUtils.create(10272, 1, bArr);
//    }
}

//final class MessageIndex {
//    static final int AUTO_CLOSE_AUDIO = 129;
//    static final int AUTO_SET_DISPLAY_SATTUS = 120;
//    static final int CAMERA_SET_PLAY_MODEL = 124;
//    static final int CAMERA_WIFI_SINGNAL_LEVEL_MSG = 122;
//    static final int CHANNEL_CREAT_FAILED = 104;
//    static final int CHANNEL_CREAT_SUCCESS = 103;
//    static final int CHANNEL_VERIFY_FAILED = 102;
//    static final int CHANNEL_VERIFY_SUCCESS = 101;
//    static final int CHECK_BIT_RATE = 118;
//    static final int CHECK_FIRMWAREVERSION = 107;
//    static final int CLOSE_AUDIO_FAILED = 112;
//    static final int CLOSE_AUDIO_SUCCESS = 114;
//    static final int CLOSE_SPEEK_FAILED = 128;
//    static final int CLOSE_SPEEK_SUCCESS = 127;
//    static final int CLOSE_VIDEO_FAILED = 137;
//    static final int CLOSE_VIDEO_SUCCESS = 139;
//    static final int CLOUD_ACCEPT_SHARE_DEVICE = 21018;
//    static final int CLOUD_ACTIVE_SCENE = 21037;
//    static final int CLOUD_CHANGE_PWD_OLD_PWD_ERROR = 21043;
//    static final int CLOUD_CHANGE_USERNAME = 21046;
//    static final int CLOUD_CHANGE_USERNAME_CODE = 21044;
//    static final int CLOUD_CHANGE_USERNAME_CODE_PWD_ERROR = 21045;
//    static final int CLOUD_CHANGE_USER_PWD = 21023;
//    static final int CLOUD_CREATE_AUTOMATION = 21038;
//    static final int CLOUD_CREAT_SCENE = 21033;
//    static final int CLOUD_DELETE_ALARM_INFO = 21031;
//    static final int CLOUD_DELETE_AUTOMATION = 21040;
//    static final int CLOUD_DELETE_DEVICE = 21012;
//    static final int CLOUD_DELETE_DEVICE_USER = 21016;
//    static final int CLOUD_DELETE_SCENE = 21035;
//    static final int CLOUD_DELETE_SHARE_INFO = 21024;
//    static final int CLOUD_EDIT_AUTOMATION = 21039;
//    static final int CLOUD_EDIT_SCENE = 21034;
//    static final int CLOUD_ERR_PHONE_INFO_NOT_REGISTERED = 20005;
//    static final int CLOUD_ERR_USERNAME_PWD = 20003;
//    static final int CLOUD_ERR_USER_NOT_REGISTERED = 20004;
//    static final int CLOUD_FORGET_PWD = 21005;
//    static final int CLOUD_GET_ALARM_INFO_LIST = 21020;
//    static final int CLOUD_GET_ALLOW_BINDING_DEVICE_LIST = 21009;
//    static final int CLOUD_GET_AUTOMATION_LIST = 21041;
//    static final int CLOUD_GET_BINDING_RESULT = 21011;
//    static final int CLOUD_GET_BINDING_TOKEN = 21010;
//    static final int CLOUD_GET_DEVICE_ACTION_INFO_LIST = 21032;
//    static final int CLOUD_GET_DEVICE_CONNECT_INFO_LIST = 21022;
//    static final int CLOUD_GET_DEVICE_LIST = 21013;
//    static final int CLOUD_GET_DEVICE_USER_LIST = 21014;
//    static final int CLOUD_GET_LATEST_FIRM_VER = 21025;
//    static final int CLOUD_GET_PUSH_INFO = 21026;
//    static final int CLOUD_GET_SCENE_LIST = 21036;
//    static final int CLOUD_GET_SHARE_INFO_LIST = 21019;
//    static final int CLOUD_GET_TOKEN = 21004;
//    static final int CLOUD_GET_USER_INFO = 21006;
//    static final int CLOUD_LOGIN = 21003;
//    static final int CLOUD_REQUEST_TIMEOUT = 20001;
//    static final int CLOUD_SECURE_CODE = 21001;
//    static final int CLOUD_SET_APP_INFO = 21008;
//    static final int CLOUD_SET_DEVICE_INFO = 21015;
//    static final int CLOUD_SET_PUSH_INFO = 21027;
//    static final int CLOUD_SET_USER_INFO = 21007;
//    static final int CLOUD_SHARE_DEVICE = 21017;
//    static final int CLOUD_SHARE_TO_USER_NOT_REGISTERED = 21028;
//    static final int CLOUD_UPLOAD_DEVICE_CONNECT_INFO = 21021;
//    static final int CLOUD_USER_HAS_BINDED = 21030;
//    static final int CLOUD_USER_HAS_LOCKED = 21042;
//    static final int CLOUD_USER_REGISTER = 21002;
//    static final int CLOUD_VERIFY_CODE_ERROR = 21029;
//    static final int CLOUD_VERIFY_CODE_EXPIRED = 21047;
//    static final int CONNECTION_BREAK = 25007;
//    static final int CONNECT_CAMERA_SUCCESS = 21002;
//    static final int CREATE_VIDEO_CHANNEL_RESULT = 119;
//    static final int DEL_CAM_SAMBA_RESULT = 10026;
//    static final int DEL_VIDEO_CLIP_RESULT = 10018;
//    static final int DISPLAY_CAMERA_VIDEO = 25006;
//    static final int DISPLAY_RATE_RESULT = 25008;
//    static final int DISPLAY_RESOLUTION = 106;
//    static final int DISPLAY_WIDTH_AND_HEIGHT = 135;
//    static final int DOWNLOAD_IMG = 25009;
//    static final int DOWNLOAD_VIDEO = 25010;
//    static final int DRAG_IMAGE_VIEW_ON_TOUCH = 25001;
//    static final int DRAG_IMAGE_VIEW_ON_TOUCH_DOWN = 25005;
//    static final int DRAG_IMAGE_VIEW_ON_TOUCH_LEFT = 25003;
//    static final int DRAG_IMAGE_VIEW_ON_TOUCH_RIGHT = 25002;
//    static final int DRAG_IMAGE_VIEW_ON_TOUCH_UP = 25004;
//    static final int FAIL = 2;
//    static final int GET_AUDIO_ENCODE_INFO_FAILED = 131;
//    static final int GET_AUDIO_ENCODE_INFO_SUCCESS = 130;
//    static final int GET_AUTO_TRACKING_SENSITIVE = 21312;
//    static final int GET_AUTO_TRACKING_TYPE = 21310;
//    static final int GET_CAMERA_SD_CARD_INFO = 21001;
//    static final int GET_CRUISE_ENABLE_STATUS = 21402;
//    static final int GET_CRUISE_POSITION_SETTING = 21400;
//    static final int GET_CURRENT_IMAGE_SIZE = 21320;
//    static final int GET_ENR = 136;
//    static final int GET_INDICATOR_LIGHT_STATUS_FINISH = 21113;
//    static final int GET_ISC5_ALARM_STATUS = 133;
//    static final int GET_OSD_STATUS_FINISH = 21118;
//    static final int GOT_SD_CARD_PERMISSION = 25011;
//    static final int MEDIA_TYPE_AUDIO = 2;
//    static final int MEDIA_TYPE_SPEAK = 3;
//    static final int MEDIA_TYPE_VIDEO = 1;
//    static final int NEED_CLEAR_VIDEO_BUFFER = 21110;
//    static final int OPEN_AUDIO_FAILED = 113;
//    static final int OPEN_AUDIO_SUCCESS = 115;
//    static final int OPEN_SPEEK_FAILED = 126;
//    static final int OPEN_SPEEK_SUCCESS = 125;
//    static final int OPEN_VIDEO_FAILED = 138;
//    static final int OPEN_VIDEO_SUCCESS = 140;
//    static final int OPEN_WIFI_CHECK = 117;
//    static final int RECEIVE_INFRARED_ALARM = 132;
//    static final int RECEIVE_ISC3_FIRMWAREVERSION = 108;
//    static final int RECEIVE_ISC3_IMAGE = 109;
//    static final int RECEIVE_REPLAY_ALARM_DATA = 21103;
//    static final int RECIEVE_ALERT_ZONE_POSITION = 3608;
//    static final int RECIEVE_DELETE_RECORD_RESULT = 21117;
//    static final int RECIEVE_FRAMERATE_BITRATE = 21300;
//    static final int RECIEVE_GET_ALERT_ZONE_ENABLE_STATUS = 3612;
//    static final int RECIEVE_GET_AP_ENCRYPT_TYPE = 21111;
//    static final int RECIEVE_RECORD_TASK_LIST = 21114;
//    static final int RECIEVE_ROTARY_RESULT = 21500;
//    static final int RECIEVE_SET_ALERT_ZONE_ENABLE_STATUS_RESULT = 3610;
//    static final int RECIEVE_SET_ALERT_ZONE_POSITION_RESULT = 3606;
//    static final int RECIEVE_SET_AP_PWD_RESULT = 21112;
//    static final int RECIEVE_SET_AUTO_TASK_RESULT = 21116;
//    static final int RECIEVE_SET_CAMERA_TIME_RESULT = 21109;
//    static final int RECIEVE_SET_MANUAL_TASK_RESULT = 21115;
//    static final int RECIEVE_SET_REPLAY_START_TIME_RESULT = 21102;
//    static final int RECIEVE_START_REPLAY_RESULT = 21101;
//    static final int RES_AP_ENCRYPT_STATUS = 10008;
//    static final int RES_BASIC_INFO = 10031;
//    static final int RES_CAM_PARAM = 10030;
//    static final int RES_CAM_SAMBA_CONNECT_STATUS = 10027;
//    static final int RES_CHANNEL_CONTROL = 10001;
//    static final int RES_CO_ALARM_INFO = 10047;
//    static final int RES_FORMAT_SD_CARD = 10042;
//    static final int RES_LOG_STORAGE = 10033;
//    static final int RES_MANUAL_RECORD_STATUS = 10013;
//    static final int RES_MOTION_ALARM = 10036;
//    static final int RES_NETWORK_LIGHT_STATUS = 10002;
//    static final int RES_NIGHT_VISION_STATUS = 10004;
//    static final int RES_OSD_STATUS = 10010;
//    static final int RES_RECORD_INFO_HOURS = 10039;
//    static final int RES_RECORD_INFO_MINUTES = 10040;
//    static final int RES_RECORD_TYPE = 10034;
//    static final int RES_REPLAY_CONTROL = 10019;
//    static final int RES_SAMBA_ENABLE = 10024;
//    static final int RES_SAMBA_PARAM = 10020;
//    static final int RES_SAMBA_STORAGE_TIME = 10028;
//    static final int RES_SAMBA_STORAGE_TYPE = 10022;
//    static final int RES_SD_CARD_INFO = 10041;
//    static final int RES_SMOKE_ALARM_INFO = 10045;
//    static final int RES_SOUND_ALARM_INFO = 10043;
//    static final int RES_TIMELAPSE_STATUS = 10015;
//    static final int RES_VIDEO_CLIP_LIST = 10017;
//    static final int RES_VIDEO_PARAM = 10006;
//    static final int ROTARY = 21200;
//    static final int ROTARY_START = 21203;
//    static final int ROTARY_STOP = 21204;
//    static final int SAVE_PIC_SUCCESS = 25000;
//    static final int SEND_COMMAND_TIMEOUT = 10000;
//    static final int SERVTYPE_STREAM_SERVER = 16;
//    static final int SETTING_PAGE_REFRESH_DATA = 116;
//    static final int SET_AP_PWD_RESULT = 10009;
//    static final int SET_AUTO_TRACKING_SENSITIVE = 21313;
//    static final int SET_AUTO_TRACKING_TYPE = 21311;
//    static final int SET_CAMERA_ALARM_STATUS = 134;
//    static final int SET_CO_ALARM_RESULT = 10048;
//    static final int SET_CRUISE_ENABLE_STATUS = 21403;
//    static final int SET_CRUISE_POSITION_SETTING = 21401;
//    static final int SET_CURRENT_IMAGE_SIZE = 21321;
//    static final int SET_LOG_STORAGE = 10032;
//    static final int SET_MANUAL_RECORD_RESULT = 10014;
//    static final int SET_MOTION_ALARM_RESULT = 10037;
//    static final int SET_NETWORK_LIGHT_RESULT = 10003;
//    static final int SET_NIGHT_VISION_RESULT = 10005;
//    static final int SET_OSD_RESULT = 10011;
//    static final int SET_RECORD_TYPE_RESULT = 10035;
//    static final int SET_SAMBA_ENABLE_RESULT = 10025;
//    static final int SET_SAMBA_PARAM_RESULT = 10021;
//    static final int SET_SAMBA_STORAGE_TIME_RESULT = 10029;
//    static final int SET_SAMBA_STORAGE_TYPE_RESULT = 10023;
//    static final int SET_SMOKE_ALARM_RESULT = 10046;
//    static final int SET_SOUND_ALARM_RESULT = 10044;
//    static final int SET_TIMELAPSE_RESULT = 10016;
//    static final int SET_TIMESTAMP_RESULT = 10012;
//    static final int SET_VIDEO_PARAM_RESULT = 10007;
//    static final int SPEEK_SERVER_START_FAILED = 929;
//    static final int SPEEK_SERVER_START_SUCCESS = 930;
//    static final int SUCCESS = 1;
//    static final int TOKEN_EXPIRED = 20002;
//    static final int TO_LEFT = 21201;
//    static final int TO_RIGHT = 21202;
//    static final int TUTK_AUTHORING = 535;
//    static final int TUTK_AVAPI_INIT_SUCCESS = 520;
//    static final int TUTK_AV_AUDIO_INFO = 11;
//    static final int TUTK_AV_CHANNEL_CREAT_FAILED = 924;
//    static final int TUTK_AV_CHANNEL_CREAT_SUCCESS = 923;
//    static final int TUTK_AV_CONNECT_ERROR = 4;
//    static final int TUTK_AV_CONNECT_MODEL = 927;
//    static final int TUTK_AV_CREAT_FAILED = 922;
//    static final int TUTK_AV_CREAT_SUCCESS = 921;
//    static final int TUTK_AV_DEINIT = 928;
//    static final int TUTK_AV_DEINIT_RECONNECT = 932;
//    static final int TUTK_AV_OTHER_ERROR = 5;
//    static final int TUTK_AV_READY_SEND = 11;
//    static final int TUTK_AV_RECEIVE_AUDIO_DATA = 8;
//    static final int TUTK_AV_RECEIVE_AVFRAME = 931;
//    static final int TUTK_AV_RECEIVE_CONTROL_DATA = 6;
//    static final int TUTK_AV_RECEIVE_DATA = 925;
//    static final int TUTK_AV_RECEIVE_DATA_TIMEOUT = 926;
//    static final int TUTK_AV_RECEIVE_VIDEO_DATA = 7;
//    static final int TUTK_AV_SEND_DATA_FAILED = 9;
//    static final int TUTK_AV_SEND_DATA_SUCC = 10;
//    static final int TUTK_AV_SEND_SPEAK_DATA_FAILED = 12;
//    static final int TUTK_AV_UID_CHECK_ERROR = 1;
//    static final int TUTK_AV_VIDEO_RATE = 10;
//    static final int TUTK_CHANNEL_CREATING = 540;
//    static final int TUTK_CREATE_SUCCESS = 100;
//    static final int TUTK_GETING_SESSIONID = 524;
//    static final int TUTK_GET_CLIENTID_SUCCESS = 530;
//    static final int TUTK_GET_SECCESSID_SUCCESS = 525;
//    static final int TUTK_GET_SESSIONID_FAILED = 526;
//    static final int TUTK_VIDEO_CREATE_SUCCESS = 545;
//    static final int UPDATE_RESULT = 10038;
//    static final int USER_SET_DISPLAY_STATUS = 121;
//    static final int VIDEO_CHANNEL_CONTROL = 2001;
//}

final class XXTEA {
    private static final int DELTA = -1640531527;

//    static IntBuffer encryptInPlace(IntBuffer data, IntBuffer key) {
//        if (key.limit() != 4) {
//            throw new IllegalArgumentException("XXTEA needs a 128-bits key");
//        }
//        if (data.limit() >= 2) {
//            int n = data.limit();
//            int rounds = (52 / data.limit()) + 6;
//            int sum = 0;
//            int z = data.get(n - 1);
//            do {
//                int y;
//                sum -= 1640531527;
//                int e = (sum >>> 2) & 3;
//                int p = 0;
//                while (p < n - 1) {
//                    y = data.get(p + 1);
//                    z = data.get(p) + ((((z >>> 5) ^ (y << 2)) + ((y >>> 3) ^ (z << 4))) ^ ((sum ^ y) + (key.get((p & 3) ^ e) ^ z)));
//                    data.put(p, z);
//                    p++;
//                }
//                y = data.get(0);
//                z = data.get(n - 1) + ((((z >>> 5) ^ (y << 2)) + ((y >>> 3) ^ (z << 4))) ^ ((sum ^ y) + (key.get((p & 3) ^ e) ^ z)));
//                data.put(p, z);
//                rounds--;
//            } while (rounds > 0);
//        }
//        return data;
//    }

//    static int[] encryptInPlace(int[] data, int[] key) {
//        encryptInPlace(IntBuffer.wrap(data), IntBuffer.wrap(key));
//        return data;
//    }

//    static byte[] encryptInPlace(byte[] data, byte[] key) {
//        encryptInPlace(ByteBuffer.wrap(data), ByteBuffer.wrap(key));
//        return data;
//    }

//    static ByteBuffer encryptInPlace(ByteBuffer data, ByteBuffer key) {
//        encryptInPlace(data.asIntBuffer(), key.asIntBuffer());
//        return data;
//    }

//    static IntBuffer encrypt(IntBuffer data, IntBuffer key) {
//        int[] copy = new int[(data.limit() - data.position())];
//        data.get(copy);
//        return encryptInPlace(IntBuffer.wrap(copy), key);
//    }

//    static int[] encrypt(int[] data, int[] key) {
//        return encrypt(IntBuffer.wrap(data), IntBuffer.wrap(key)).array();
//    }

//    static ByteBuffer encrypt(ByteBuffer data, ByteBuffer key) {
//        byte[] copy = new byte[(data.limit() - data.position())];
//        data.get(copy);
//        return encryptInPlace(ByteBuffer.wrap(copy), key);
//    }

//    static byte[] encrypt(byte[] data, byte[] key) {
//        return encrypt(ByteBuffer.wrap(data), ByteBuffer.wrap(key)).array();
//    }

    private static IntBuffer decryptInPlace(IntBuffer data, IntBuffer key) {
        if (key.limit() != 4) {
            throw new IllegalArgumentException("XXTEA needs a 128-bits key");
        }
        if (data.limit() >= 2) {
            int y = data.get(0);
            int sum = ((52 / data.limit()) + 6) * DELTA;
            int l = data.limit();
            do {
                int z;
                int e = (sum >>> 2) & 3;
                int p = data.limit() - 1;
                while (p > 0) {
                    z = data.get(p - 1);
                    y = data.get(p) - ((((z >>> 5) ^ (y << 2)) + ((y >>> 3) ^ (z << 4))) ^ ((sum ^ y) + (key.get((p & 3) ^ e) ^ z)));
                    data.put(p, y);
                    p--;
                }
                z = data.get(l - 1);
                y = data.get(0) - ((((z >>> 5) ^ (y << 2)) + ((y >>> 3) ^ (z << 4))) ^ ((sum ^ y) + (key.get((p & 3) ^ e) ^ z)));
                data.put(0, y);
                sum += 1640531527;
            } while (sum != 0);
        }
        return data;
    }

//    static int[] decryptInPlace(int[] data, int[] key) {
//        decryptInPlace(IntBuffer.wrap(data), IntBuffer.wrap(key));
//        return data;
//    }

//    static byte[] decryptInPlace(byte[] data, byte[] key) {
//        decryptInPlace(ByteBuffer.wrap(data), ByteBuffer.wrap(key));
//        return data;
//    }

    private static ByteBuffer decryptInPlace(ByteBuffer data, ByteBuffer key) {
        decryptInPlace(data.asIntBuffer(), key.asIntBuffer());
        return data;
    }

//    static IntBuffer decrypt(IntBuffer data, IntBuffer key) {
//        int[] copy = new int[(data.limit() - data.position())];
//        data.get(copy);
//        return decryptInPlace(IntBuffer.wrap(copy), key);
//    }

//    static int[] decrypt(int[] data, int[] key) {
//        return decrypt(IntBuffer.wrap(data), IntBuffer.wrap(key)).array();
//    }

    private static ByteBuffer decrypt(ByteBuffer data, ByteBuffer key) {
        byte[] copy = new byte[(data.limit() - data.position())];
        data.get(copy);
        return decryptInPlace(ByteBuffer.wrap(copy), key);
    }

    static byte[] decrypt(byte[] data, byte[] key) {
        return decrypt(ByteBuffer.wrap(data), ByteBuffer.wrap(key)).array();
    }

//    public boolean BytesEquals(byte[] src, byte[] dst, int len) {
//        for (int i = 0; i < len; i++) {
//            if (src[i] != dst[i]) {
//                return false;
//            }
//        }
//        return true;
//    }
}
