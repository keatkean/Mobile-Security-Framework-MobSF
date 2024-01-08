// sensitive data access - local_data.js
Java.perform(function() {
    // Print Initalisation
    send("[Initialised] SensitiveDataAccess");
    // Config
    var CONFIG = {
        // if TRUE print stack trace
        printStackTrace: false
    };
    // Declaring Android Objects
    var ContentResolver = Java.use("android.content.ContentResolver");
    // Content Resolver Query
    ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'android.os.Bundle', 'android.os.CancellationSignal').implementation = function (uri, projection, queryArgs, cancellationSignal) {
        ContentType(uri.toString());
        return this.query(uri, projection, queryArgs, cancellationSignal);
    };
    // helper functions
    function stackTrace() {
        Java.perform(function() {
            send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        });
    }
    function ContentType(uri) {
        if (uri === 'content://com.android.contacts/contacts') {
            send("[Access.Contacts] Application Accessing Contacts from -> content://com.android.contacts/contacts");
            if (CONFIG.printStackTrace) {stackTrace();}
        } else if (uri === 'content://call_log/calls') {
            send("[Access.CallLogs] Application Accessing Call Logs from -> content://call_log/calls");
            if (CONFIG.printStackTrace) {stackTrace();}
        } else if (uri === 'content://sms/') {
            send("[Access.SMS] Application Accessing Call Logs from -> content://sms/");
            if (CONFIG.printStackTrace) {stackTrace();}
        }
    }
});

// media recording - media_recorder.js
Java.perform(function () {
    // Print Initalisation
    send("[Initialised] MediaRecorder");
    // Config
    var CONFIG = {
        // if TRUE print stack trace
        printStackTrace: false
    };
    // Initialise Android Objects
    var mediaRecorder = Java.use('android.media.MediaRecorder');
    var audioRecord = Java.use('android.media.AudioRecord');
    // Set audio source
    mediaRecorder.setAudioSource.overload('int').implementation = function (audioSource) {
        send('[MediaRecorder.Audio] Setting audio source to -> ' + audioSource);
        if (CONFIG.printStackTrace) {stackTrace();}
        return this.setAudioSource(audioSource);
    };
    // Set video source
    mediaRecorder.setVideoSource.overload('int').implementation = function (videoSource) {
        send('[MediaRecorder.Video] Setting video source to -> ' + videoSource);
        if (CONFIG.printStackTrace) {stackTrace();}
        return this.setVideoSource(audioSource);
    };
    // Set output format
    mediaRecorder.setOutputFormat.overload('int').implementation = function (outputFormat) {
        var outputFormatValue = {
            0: 'DEFAULT',
            1: 'THREE_GPP',
            2: 'MPEG_4',
            3: 'RAW_AMR',
            8: 'MPEG_2_TS',
            9: 'WEBM',
            11: 'OGG'
        };
        try {
            send('[MediaRecorder] Setting output format -> ' + outputFormatValue[outputFormat]);
        } catch (err) {
            send('[MediaRecorder] Setting output format -> ' + outputFormat);
        }
        if (CONFIG.printStackTrace) {stackTrace();}
        return this.setOutputFormat(outputFormat);
    };
    // Set audio encoder
    mediaRecorder.setAudioEncoder.overload('int').implementation = function (audioEncoder) {
        var audioEncoderValue = {
            0: 'DEFAULT',
            4: 'HE_AAC',
            6: 'VORBIS',
            7: 'OPUS'
        };
        try {
            send('[MediaRecorder.Audio] Setting audio encoder -> ' + audioEncoderValue[audioEncoder]);
        } catch (err) {
            send('[MediaRecorder.Audio] Setting audio encoder -> ' + audioEncoder);
        }
        if (CONFIG.printStackTrace) {stackTrace();}
        return this.setAudioEncoder(audioEncoder);
    };
    // Set audio encoder
    mediaRecorder.setVideoEncoder.overload('int').implementation = function (videoEncoder) {
        var videoEncoderValue = {
            0: 'DEFAULT',
            1: 'H263',
            2: 'H264',
            3: 'MPEG_4_SP',
            4: 'VP8',
            5: 'HEVC',
            6: 'VP9',
            7: 'DOLBY_VISION'
        };
        try {
            send('[MediaRecorder.Video] Setting video encoder -> ' + videoEncoderValue[videoEncoder]);
        } catch (err) {
            send('[MediaRecorder.Video] Setting video encoder -> ' + videoEncoder);
        }
        if (CONFIG.printStackTrace) {stackTrace();}
        return this.setVideoEncoder(videoEncoder);
    };
    // Set output file
    mediaRecorder.setOutputFile.overload('java.io.FileDescriptor').implementation = function (fileDescriptor) {
        send('[MediaRecorder] Setting output file');
        if (CONFIG.printStackTrace) {stackTrace();}
        return this.setOutputFile(fileDescriptor);
    };
    mediaRecorder.setOutputFile.overload('java.lang.String').implementation = function (filePath) {
        send('[MediaRecorder] Setting output file -> ' + filePath);
        if (CONFIG.printStackTrace) {stackTrace();}
        return this.setOutputFile(filePath);
    };
    mediaRecorder.setOutputFile.overload('java.io.File').implementation = function (file) {
        send('[MediaRecorder] Setting output file -> ' + file.getPath());
        if (CONFIG.printStackTrace) {stackTrace();}
        return this.setOutputFile(file);
    };
    // Start recording
    mediaRecorder.start.implementation = function () {
        send('[MediaRecorder] Starting recording');
        if (CONFIG.printStackTrace) {stackTrace();}
        return this.start();
    };
    // Set audio source
    audioRecord.startRecording.overload().implementation = function () {
        send('[AudioRecord] Starting Audio Recording');
        if (CONFIG.printStackTrace) {stackTrace();}
        return this.startRecording();
    };
    audioRecord.startRecording.overload('android.media.MediaSyncEvent').implementation = function (mediaSyncEvent) {
        send('[AudioRecord] Starting Audio Recording');
        if (CONFIG.printStackTrace) {stackTrace();}
        return this.startRecording(mediaSyncEvent);
    };
    // Stack Trace Function
    function stackTrace() {
        Java.perform(function() {
            send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        });
    }
});

// dex class loader - dex.js
Java.perform(function() {
    // Print Initalisation
    send("[Initialised] DexClassLoader");
    // Config
    var CONFIG = {
        // if TRUE print stack trace
        printStackTrace: false,
        // if TRUE print dex file contents
        dump_files: true,
    };
    // Declaring Android Objects
    var dalvikDexClassLoader = Java.use("dalvik.system.DexClassLoader");
    dalvikDexClassLoader.$init.implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
        send("[DexClassLoader] Loaded Classes From: " + dexPath);
        //if (CONFIG.dump_files) {b2s(buffer);}
        if (CONFIG.printStackTrace) {stackTrace();}
        return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
    };
    // helper functions
    function stackTrace() {
        Java.perform(function() {
            send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        });
    }
});

// bypass system checks - system_checks.js
Java.perform(function() {
    // Print Initalisation
    send("[Initialised] SystemChecks");
    // Config
    var CONFIG = {
        // if TRUE print stack trace
        printStackTrace: false
    };
    // Spoofed Data
    var phoneNumber = '+49 1522 343333';
    var IMEINumber = '35253108' + '852947' + '2';
    var SIMOperatorCode = '049' + '262';
    var SIMOperatorName = 'Vodafone';
    var countryCode = 'deu';
    var bluetoothMACAddress = 'F7:B0:AB:E9:2B:B1';
    var wifiMACAddress = 'EB:FD:C5:32:9D:75';
    var routerMACAddress = '84:29:CD:A7:35:BA';
    var wifiSSID = 'CorporateNetwork01';
    var serial = ''
    // Declaring Android Objects
    var telephonyManager = Java.use('android.telephony.TelephonyManager');
    var build = Java.use('android.os.Build')
    var wifiInfo = Java.use('android.net.wifi.WifiInfo');
    var bluetoothAdapter = Java.use('android.bluetooth.BluetoothAdapter');
    var securityExecption = Java.use('java.lang.SecurityException')
    // BUILD Get Serial Number
    build.getSerial.implementation = function() {
        send('[SystemCheck.DeviceSerial] Application checking for Device serial, returning -> ' + serial);
        if (CONFIG.printStackTrace) {stackTrace();}
        return serial;
    };
    // Telephony Manager Get Phone Number
    telephonyManager.getLine1Number.overloads[0].implementation = function() {
        send('[SystemCheck.PhoneNumber] Application checking for Phone Number, returning -> ' + phoneNumber);
        if (CONFIG.printStackTrace) {stackTrace();}
        return phoneNumber;
    };
    // Telephony Manager Get Subscriber ID (IMSI)
    telephonyManager.getSubscriberId.overload().implementation = function() {
        exception = securityExecption.$init();
        send('[SystemCheck.SubscriberID] Application checking for Subscriber ID, returning -> ' + exception);
        if (CONFIG.printStackTrace) {stackTrace();}
        return exception;
    };
    // Telephony Manager Get Device ID (IMEI)
    telephonyManager.getDeviceId.overloads().implementation = function() {
        send('[SystemCheck.IMEI] Application asks for device IMEI, returning -> ' + IMEINumber);
        if (CONFIG.printStackTrace) {stackTrace();}
        return IMEINumber;
    };
    telephonyManager.getDeviceId.overloads('int').implementation = function(slot) {
        send('[SystemCheck.IMEI] Application asks for device IMEI, returning -> ' + IMEINumber);
        if (CONFIG.printStackTrace) {stackTrace();}
        return IMEINumber;
    };
    // Telephony Manager Get IMEI Number
    telephonyManager.getImei.overloads[0].implementation = function() {
        send('[SystemCheck.IMEI] Application checking for device IMEI, returning -> ' + IMEINumber);
        if (CONFIG.printStackTrace) {stackTrace();}
        return IMEINumber;
    };
    telephonyManager.getImei.overloads[1].implementation = function(slot) {
        send('[SystemCheck.IMEI] Application checking for device IMEI, returning -> ' + IMEINumber);
        if (CONFIG.printStackTrace) {stackTrace();}
        return IMEINumber;
    };
    // Telephony Manager Get SIM Operator
    telephonyManager.getSimOperator.overload().implementation = function() {
        send('[SystemCheck.SIMOperator] Application checking for SIM operator, returning -> ' + SIMOperatorCode);
        if (CONFIG.printStackTrace) {stackTrace();}
        return SIMOperatorCode;
    };
    telephonyManager.getSimOperator.overload('int').implementation = function(sm) {
        send('[SystemCheck.SIMOperator] Applicaiton checking for SIM operator, returning -> ' + SIMOperatorCode);
        if (CONFIG.printStackTrace) {stackTrace();}
        return SIMOperatorCode;
    };
    // Telephony Manager Get SIM Operator Name
    telephonyManager.getSimOperatorName.overload().implementation = function() {
        send('[SystemCheck.SIMOperatorName] Application checking for SIM operator name, returning -> ' + SIMOperatorName);
        if (CONFIG.printStackTrace) {stackTrace();}
        return SIMOperatorName;
    };
    // Telephony Manager Get SIM Serial Number
    telephonyManager.getSimSerialNumber.overload().implementation = function() {
        exception = securityExecption.$init();
        send('[SystemCheck.SIMSerial] Application checking for SIM Serial Number, returning -> ' + exception);
        if (CONFIG.printStackTrace) {stackTrace();}
        return exception;
    }
    // Telephony Manager Get SIM Country ISO
    telephonyManager.getSimCountryIso.overload().implementation = function() {
        send('[SystemCheck.Country] Application checking for SIM Country ISO, returning -> ' + countryCode);
        if (CONFIG.printStackTrace) {stackTrace();}
        return countryCode;
    };
    // Telephony Manager Get Network Country ISO
    telephonyManager.getNetworkCountryIso.overload().implementation = function() {
        send('[SystemCheck.Country] Application checking for Network Country ISO, returning -> ' + countryCode);
        if (CONFIG.printStackTrace) {stackTrace();}
        return countryCode;
    };
    telephonyManager.getNetworkCountryIso.overload('int').implementation = function() {
        send('[SystemCheck.Country] Application checking for Network Country ISO, returning -> ' + countryCode);
        if (CONFIG.printStackTrace) {stackTrace();}
        return countryCode;
    };
    // Bluetooth Addapter Get MAC Address
    bluetoothAdapter.getAddress.implementation = function() {
        send('[NetworkCheck.BluetoothMAC] Application chekcing Bluetooth MAC Address, returning -> ' + bluetoothMACAddress);
        if (CONFIG.printStackTrace) {stackTrace();}
        return bluetoothMACAddress;
    };
    // Wifi Info Get MAC Address
    wifiInfo.getMacAddress.implementation = function() {
        send('[NetworkCheck.WifiMAC] Application checking Wifi MAC Address, returning -> ' + wifiMACAddress);
        if (CONFIG.printStackTrace) {stackTrace();}
        return wifiMACAddress;
    };
    // Wifi Info Get SSID
    wifiInfo.getSSID.implementation = function() {
        send('[NetworkCheck.WifiSSID] Applicaiton checking Wifi SSID, returning -> ' + wifiSSID);
        if (CONFIG.printStackTrace) {stackTrace();}
        return wifiSSID;
    };
    // Wifi Info Get Router MAC Address
    wifiInfo.getBSSID.implementation = function() {
        send('[NetworkCheck.RouterMAC] Application checking Router MAC Address, returning -> ' + routerMACAddress);
        if (CONFIG.printStackTrace) {stackTrace();}
        return routerMACAddress;
    };
    // Stack Trace Function
    function stackTrace() {
        Java.perform(function() {
            send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        });
    };
});

// hiding application icon - hide_app.js
Java.perform(function() {
    // Print Initalisation
    send("[Initialised] HideApp");
    // Config
    var CONFIG = {
        // if TRUE print stack trace
        printStackTrace: false,
    };
    // Declaring Android Objects
    var applicationPackageManager = Java.use("android.app.ApplicationPackageManager");
    var packageManager = Java.use("android.content.pm.PackageManager")
    // Hide Application (Application Pacakge Manager)
    applicationPackageManager.setComponentEnabledSetting.overload('android.content.ComponentName', 'int', 'int').implementation = function (componentName, newState, flags) {
        if (newState === 2 && flags === 1) {
            send("[HideApp] Hidding Application");
            if (CONFIG.printStackTrace) {stackTrace();}
        }
        return this.setComponentEnabledSetting(componentName, newState, flags);
    };
    // Hide Application (Package Manager)
    packageManager.setComponentEnabledSetting.overload('android.content.ComponentName', 'int', 'int').implementation = function (componentName, newState, flags) {
        if (newState === 2 && flags === 1) {
            send("[HideApp] Hidding Application");
            if (CONFIG.printStackTrace) {stackTrace();}
        }
        return this.setComponentEnabledSetting(componentName, newState, flags);
    };
    // helper functions
    function stackTrace() {
        Java.perform(function() {
            send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        });
    };
});

// obfuscation base64 - encoding.js
Java.perform(function() {
    // Adapted from https://codeshare.frida.re/@masihyeganeh/re/
    // Print Initalisation
    send("[Initialised] Base64");
    // Config
    var CONFIG = {
        // if TRUE print stack trace
        printStackTrace: false
    };
    // Declaring Android Objects
    var b64Def = Java.use('android.util.Base64');
    var b64DefEncode_2 = b64Def.encode.overload('[B', 'int');
    var b64DefEncode_3 = b64Def.encode.overload('[B', 'int', 'int', 'int');
    var b64DefEncodeToString_2 = b64Def.encodeToString.overload('[B', 'int');
    var b64DefEncodeToString_3 = b64Def.encodeToString.overload('[B', 'int', 'int', 'int');
    var b64DefDecode_1 = b64Def.decode.overload('java.lang.String', 'int');
    var b64DefDecode_2 = b64Def.decode.overload('[B', 'int');
    var b64DefDecode_3 = b64Def.decode.overload('[B', 'int', 'int', 'int');
    // Base64 Encoding Hooks
    b64DefEncode_2.implementation = function(arr, flag) {
        var result = b64DefEncode_2.call(this, arr, flag);
        send("[Base64] Encode: " + JSON.stringify(arr) + " | Result: " + result);
        if (CONFIG.printStackTrace) {
            Java.perform(function() {
                send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
            });
        }
        return result;
    };
    b64DefEncode_3.implementation = function(arr, off, len, flag) {
        var result = b64DefEncode_3.call(this, arr, off, len, flag);
        send("[Base64] Encode: [" + off + "," + len + "] " + JSON.stringify(arr) + "\n[Base64] Result: " + result);
        if (CONFIG.printStackTrace) {
            Java.perform(function() {
                send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
            });
        }
        return result;
    };
    // Base64 Encode to String Hooks
    b64DefEncodeToString_2.implementation = function(arr, flag) {
        var result = b64DefEncodeToString_2.call(this, arr, flag);
        send("[Base64] EncodeToString: " + JSON.stringify(arr) + " | Result: " + result);
        if (CONFIG.printStackTrace) {
            Java.perform(function() {
                send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
            });
        }
        return result;
    };
    b64DefEncodeToString_3.implementation = function(arr, off, len, flag) {
        var result = b64DefEncodeToString_3.call(this, arr, off, len, flag);
        send("[Base64] EncodeToString: [" + off + "," + len + "] " + JSON.stringify(arr) + " | Result: " + result);
        if (CONFIG.printStackTrace) {
            Java.perform(function() {
                send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
            });
        }
        return result;
    };
    // Base64 Decoding Hooks
    b64DefDecode_1.implementation = function(str, flag) {
        var result = b64DefDecode_1.call(this, str, flag);
        send("[Base64] Decode: " + str + " | Result : " + result + " (" + b2s(result) + ")");
        if (CONFIG.printStackTrace) {
            Java.perform(function() {
                send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
            });
        }
        return result;
    };
    b64DefDecode_2.implementation = function(arr, flag) {
        var result = b64DefDecode_2.call(this, arr, flag);
        send("[Base64] Decode: " + JSON.stringify(arr) + " | Result : " + result + " (" + b2s(result) + ")");
        if (CONFIG.printStackTrace) {
            Java.perform(function() {
                send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
            });
        }
        return result;
    };
    b64DefDecode_3.implementation = function(arr, off, len, flag) {
        var result = b64DefDecode_3.call(this, arr, off, len, flag);
        send("[Base64] Decode: [" + off + "," + len + "] " + JSON.stringify(arr) + " | Result : " + result + " (" + b2s(result) + ")");
        if (CONFIG.printStackTrace) {
            Java.perform(function() {
                send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
            });
        }
        return result;
    };
    // Formatting functions
    function b2s(array) {
        var result = "";
        for (var i = 0; i < array.length; i++) {
            result += String.fromCharCode(modulus(array[i], 256));
        }
        return result;
    }
    function modulus(x, n) {
        return ((x % n) + n) % n;
    }
});

// obfuscation encryption - encryption.js
Java.perform(function () {
    // https://codeshare.frida.re/@dzonerzy/aesinfo/
    // Print Initalisation
    send("[Initialised] Encryption");

    // Config
    var CONFIG = {
        // if TRUE print Key as hex dump
        keyHexDump: false,
        // if TRUE print Initialization Vector as hex dump
        ivHexDump: false,
        // if TRUE print Encryption/Decryption input as hex dump
        operationInput: false,
        // if TRUE print Encryption/Decryption output as hex dump
        operationOutput: false
    };

    var complete_bytes = new Array();
    var index = 0;

    var secretKeySpecDef = Java.use('javax.crypto.spec.SecretKeySpec');
    var ivParameterSpecDef = Java.use('javax.crypto.spec.IvParameterSpec');
    var cipherDef = Java.use('javax.crypto.Cipher');

    var cipherDoFinal_1 = cipherDef.doFinal.overload();
    var cipherDoFinal_2 = cipherDef.doFinal.overload('[B');
    var cipherDoFinal_3 = cipherDef.doFinal.overload('[B', 'int');
    var cipherDoFinal_4 = cipherDef.doFinal.overload('[B', 'int', 'int');
    var cipherDoFinal_5 = cipherDef.doFinal.overload('[B', 'int', 'int', '[B');
    var cipherDoFinal_6 = cipherDef.doFinal.overload('[B', 'int', 'int', '[B', 'int');

    var cipherUpdate_1 = cipherDef.update.overload('[B');
    var cipherUpdate_2 = cipherDef.update.overload('[B', 'int', 'int');
    var cipherUpdate_3 = cipherDef.update.overload('[B', 'int', 'int', '[B');
    var cipherUpdate_4 = cipherDef.update.overload('[B', 'int', 'int', '[B', 'int');

    var secretKeySpecDef_init_1 = secretKeySpecDef.$init.overload('[B', 'java.lang.String');
    var secretKeySpecDef_init_2 = secretKeySpecDef.$init.overload('[B', 'int', 'int', 'java.lang.String');

    var ivParameterSpecDef_init_1 = ivParameterSpecDef.$init.overload('[B');
    var ivParameterSpecDef_init_2 = ivParameterSpecDef.$init.overload('[B', 'int', 'int');

    secretKeySpecDef_init_1.implementation = function (arr, alg) {
        var key = b2s(arr);
        send("[Encryption] Creating " + alg + " secret key, plaintext: " + (CONFIG.keyHexDump ? ("\n" + hexdump(key)) : key));
        return secretKeySpecDef_init_1.call(this, arr, alg);
    }

    secretKeySpecDef_init_2.implementation = function (arr, off, len, alg) {
        var key = b2s(arr);
        send("[Encryption] Creating " + alg + " secret key, plaintext: " + (CONFIG.keyHexDump ? ("\n" + hexdump(key)) : key));
        return secretKeySpecDef_init_2.call(this, arr, off, len, alg);
    }

    ivParameterSpecDef_init_1.implementation = function(arr)
    {
        var iv = b2s(arr);
        send("[Encryption] Creating IV: " + (CONFIG.ivHexDump ? ("\n" + hexdump(iv)) : iv));
        return ivParameterSpecDef_init_1.call(this, arr);
    }

    ivParameterSpecDef_init_2.implementation = function(arr, off, len)
    {
        var iv = b2s(arr);
        send("[Encryption] Creating IV, plaintext: " + (CONFIG.ivHexDump ? ("\n" + hexdump(iv)) : iv));
        return ivParameterSpecDef_init_2.call(this, arr, off, len);
    }

    cipherDoFinal_1.implementation = function () {
        var ret = cipherDoFinal_1.call(this);
        info(this.getIV(), this.getAlgorithm(), complete_bytes, ret);
        return ret;
    }

    cipherDoFinal_2.implementation = function (arr) {
        addtoarray(arr);
        var ret = cipherDoFinal_2.call(this, arr);
        info(this.getIV(), this.getAlgorithm(), complete_bytes, ret);
        return ret;
    }

    cipherDoFinal_3.implementation = function (arr, a) {
        addtoarray(arr);
        var ret = cipherDoFinal_3.call(this, arr, a);
        info(this.getIV(), this.getAlgorithm(), complete_bytes, ret);
        return ret;
    }

    cipherDoFinal_4.implementation = function (arr, a, b) {
        addtoarray(arr);
        var ret = cipherDoFinal_4.call(this, arr, a, b);
        info(this.getIV(), this.getAlgorithm(), complete_bytes, ret);
        return ret;
    }

    cipherDoFinal_5.implementation = function (arr, a, b, c) {
        addtoarray(arr);
        var ret = cipherDoFinal_5.call(this, arr, a, b, c);
        info(this.getIV(), this.getAlgorithm(), complete_bytes, ret);
        return ret;
    }

    cipherDoFinal_6.implementation = function (arr, a, b, c, d) {
        addtoarray(arr);
        var ret = cipherDoFinal_6.call(this, arr, a, b, c, d);
        info(this.getIV(), this.getAlgorithm(), complete_bytes, c);
        return ret;
    }

    cipherUpdate_1.implementation = function (arr) {
        addtoarray(arr);
        return cipherUpdate_1.call(this, arr);
    }

    cipherUpdate_2.implementation = function (arr, a, b) {
        addtoarray(arr);
        return cipherUpdate_2.call(this, arr, a, b);
    }

    cipherUpdate_3.implementation = function (arr, a, b, c) {
        addtoarray(arr);
        return cipherUpdate_3.call(this, arr, a, b, c);
    }

    cipherUpdate_4.implementation = function (arr, a, b, c, d) {
        addtoarray(arr);
        return cipherUpdate_4.call(this, arr, a, b, c, d);
    }


    // Formatting functions
    function info(iv, alg, plain, encoded) {
        send("[Encryption] Performing encryption/decryption" + 
        (iv ? ("\nInitialization Vector: \n" + hexdump(b2s(iv))) : ("\nInitialization Vector: " + iv)) + 
        "\nAlgorithm: " + alg + 
        "\nIn: \n" + (CONFIG.operationInput ? hexdump(b2s(plain)) : b2s(plain)) + 
        "\nOut: \n" + (CONFIG.operationOutput ? hexdump(b2s(encoded)) : b2s(encoded)));
        complete_bytes = [];
        index = 0;
    }

    function hexdump(buffer, blockSize) {
        blockSize = blockSize || 16;
        var lines = [];
        var hex = "0123456789ABCDEF";
        for (var b = 0; b < buffer.length; b += blockSize) {
            var block = buffer.slice(b, Math.min(b + blockSize, buffer.length));
            var addr = ("0000" + b.toString(16)).slice(-4);
            var codes = block.split('').map(function (ch) {
                var code = ch.charCodeAt(0);
                return " " + hex[(0xF0 & code) >> 4] + hex[0x0F & code];
            }).join("");
            codes += "   ".repeat(blockSize - block.length);
            var chars = block.replace(/[\\x00-\\x1F\\x20]/g, '.');
            chars += " ".repeat(blockSize - block.length);
            lines.push(addr + " " + codes + "  " + chars);
        }
        return lines.join("\n");
    }

    function b2s(array) {
        var result = "";
        for (var i = 0; i < array.length; i++) {
            result += String.fromCharCode(modulus(array[i], 256));
        }
        return result;
    }

    function modulus(x, n) {
        return ((x % n) + n) % n;
    }

    function addtoarray(arr) {
        for (var i = 0; i < arr.length; i++) {
            complete_bytes[index] = arr[i];
            index = index + 1;
        }
    }
});

// check file writable - file_writeable_check.js
var fileMap = {}; // A map to store file paths for each instance
Java.perform(function() {
    var File = Java.use('java.io.File');
    var FileInputStream = Java.use('java.io.FileInputStream');
    var FileOutputStream = Java.use('java.io.FileOutputStream');
    var StringCls = Java.use('java.lang.String'); // Add this line

    FileInputStream.$init.overload('java.io.File').implementation = function(file) {
        send('FileInputStream was created for: ' + file.getAbsolutePath());
        fileMap[this.hashCode()] = file.getAbsolutePath(); // Store file path
        return this.$init(file);
    };

    FileOutputStream.$init.overload('java.io.File').implementation = function(file) {
        send('FileOutputStream was created for: ' + file.getAbsolutePath());
        fileMap[this.hashCode()] = file.getAbsolutePath(); // Store file path
        return this.$init(file);
    };

    // Hook write(int b) method
    FileOutputStream.write.overload('int').implementation = function(b) {
        var filePath = fileMap[this.hashCode()];  // Get the file path

        // Create a byte array from the int and convert to a string
        var singleByteArray = Java.array('byte', [b]);
        var str = StringCls.$new(singleByteArray, 0, 1, "UTF-8");

        send('Warning: Data(int) being written: ' + str + ' at filepath: ' + filePath);

        return FileOutputStream.write.overload('int').call(this, b);
    };


// Hook write(byte[] b) method
FileOutputStream.write.overload('[B').implementation = function(b) {
    var filePath = fileMap[this.hashCode()];  // Get the file path

    // Convert the byte array to a human-readable string
    var byteArray = Java.array('byte', b);
    var humanReadableString = StringCls.$new(byteArray, "UTF-8");

    send('Warning: Data(bytes) being written in human-readable form: ' + humanReadableString + ' at filepath: ' + filePath);

    // Check for large write
    if (b.length > 1024 * 1024) {
        send('WARNING: Large write operation: ' + b.length + ' bytes');
    } else {
        send('No large write operations detected')
    }
    return FileOutputStream.write.overload('[B').call(this, b);
};

// Hook write(byte[] b, int off, int len) method
FileOutputStream.write.overload('[B', 'int', 'int').implementation = function(b, off, len) {
    var filePath = fileMap[this.hashCode()];  // Get the file path

    // Convert the part of the byte array to a human-readable string
    var partByteArray = Java.array('byte', Array.from(b).slice(off, off + len));
    var humanReadableString = StringCls.$new(partByteArray, "UTF-8");

    send('Warning: Data(bytes and int) being written in human-readable form: ' + humanReadableString + ' at filepath: ' + filePath);

    // Check for large write
    if (len > 1024 * 1024) {
        send('WARNING: Large write operation: ' + len + ' bytes');
    } else {
        send('No large write operations detected')
    }
    return FileOutputStream.write.overload('[B', 'int', 'int').call(this, b, off, len);
};
    File.setWritable.overload('boolean', 'boolean').implementation = function(writable, ownerOnly) {
        // If the file is being set as writable, warn the user
        if (writable) {
            send('WARNING: Attempt to set file as writable: ' + this.getAbsolutePath());
        }
        // If the file is not being set as writable, also log this info
        else {
            send('setWritable called, but file is not being set as writable: ' + this.getAbsolutePath());
        }
        return this.setWritable(writable, ownerOnly);
    };
});

// intercept traffic - Intercept_traffic.js
Java.perform(function() {
    try {
        var OkHttpClient;
        try {
            OkHttpClient = Java.use('okhttp3.OkHttpClient');
        } catch (error) {
            console.error("Error: Network Traffic not found.");
            return;
        }
        var Buffer = Java.use('okio.Buffer');
        var ResponseBody = Java.use('okhttp3.ResponseBody');
        var Response = Java.use('okhttp3.Response');
        var Base64 = Java.use('android.util.Base64'); // Import Base64
        var GZIPInputStream = Java.use('java.util.zip.GZIPInputStream');
        var InputStreamReader = Java.use('java.io.InputStreamReader');
        var BufferedReader = Java.use('java.io.BufferedReader');

        OkHttpClient.newCall.overload('okhttp3.Request').implementation = function(request) {
            send("URL: " + request.url().toString());
            send("Method: " + request.method());

            var headers = request.headers();
            for(var i = 0; i < headers.size(); i++) {
                send(headers.name(i) + ": " + headers.value(i));
            }

            var body = request.body();
            if(body !== null) {
                var buffer = Buffer.$new();
                body.writeTo(buffer);
                var bodyBytes = buffer.readByteArray();
                var strBody = Base64.encodeToString(bodyBytes, 0); // use Base64 encoding
                // send("Encoded Request body: " + strBody);
                // Decode and ungzip the body
                var decodedBytes = Base64.decode(strBody, 0);
                var byteArrayInputStream = Java.use('java.io.ByteArrayInputStream').$new(decodedBytes);
                var gzipInputStream = GZIPInputStream.$new(byteArrayInputStream);
                var bufferedReader = BufferedReader.$new(InputStreamReader.$new(gzipInputStream, "UTF-8"));
                var stringBuilder = Java.use('java.lang.StringBuilder').$new();
                var line;
                while ((line = bufferedReader.readLine()) !== null) {
                    stringBuilder.append(line);
                }
                bufferedReader.close();
                gzipInputStream.close();
                send(stringBuilder.toString());
            }

            var call = this.newCall(request);
            call.execute.implementation = function() {
                var response = this.execute();
                if(response.body() !== null) {
                    var responseBodyString = response.body().string();
                    send("Response body: " + responseBodyString);

                    var mediaType = response.body().contentType();
                    var responseBody = ResponseBody.create(mediaType, responseBodyString);
                    response = Response.newBuilder().body(responseBody).build();
                }
                return response;
            };
            return call;
        };
    } catch(error) {
        console.error("Error: " + error);
    }
});

// monitor network usage - network.js
Java.perform(function() {

    // Config
    var CONFIG = {
        // if TRUE monitor network packets metric
        networkPacketsMetric: false,
        // if TRUE monitor network bytes metric
        networkBytesMetric: false,
        // polling interval for network metrics in milliseconds (checks will only run if networkPacketsMetric or networkBytesMetric is set to true)
        metricPollingInterval: 1000,
    };



    // Network Sockets
    var SocketOutputStream = Java.use('java.net.SocketOutputStream');
    var SocketInputStream = Java.use('java.net.SocketInputStream');

    // Network bytes
    var totalBytesSent = 0;
    var totalBytesReceived = 0;

    function trackBytes() {
        return("Total Bytes Sent: " + totalBytesSent + "\nTotal Bytes Received: " + totalBytesReceived);
    }

    SocketOutputStream.write.overload('[B', 'int', 'int').implementation = function(buffer, byteOffset, byteCount) {
        totalBytesSent += byteCount;
        this.write.call(this, buffer, byteOffset, byteCount);
    };

    SocketInputStream.read.overload('[B', 'int', 'int').implementation = function(buffer, byteOffset, byteCount) {
        var result = this.read.call(this, buffer, byteOffset, byteCount);
        if(result > 0) {
            totalBytesReceived += result;
        }
        return result;
    };



    // Network Packets
    var totalPacketsSent = 0;
    var totalPacketsReceived = 0;

    function trackPackets() {
        return("Total Packets Sent: " + totalPacketsSent + "\nTotal Packets Received: " + totalPacketsReceived);
    }

    function byteArrayToAscii(byteArr, off, len) {
        var asciiString = '';
        for (var i = off; i < off + len; i++) {
            var decimal = byteArr[i];
            asciiString += String.fromCharCode(decimal);
        }
        return asciiString;
    }

    SocketInputStream.socketRead0.implementation = function(fd, byteArr, off, len, timeout) {
        var result = this.socketRead0(fd, byteArr, off, len, timeout);

        if (result > 0) {
            totalPacketsReceived++;
            var asciiData = byteArrayToAscii(byteArr, off, result);
            var logMessage = '--------------------\nReceived data:\nASCII: ' + asciiData;
            send(logMessage);
        }
        return result;
    };

    SocketOutputStream.socketWrite0.implementation = function(fd, byteArr, off, len) {
        var result = this.socketWrite0(fd, byteArr, off, len);

        if (len > 0) {
            totalPacketsSent++;
            var asciiData = byteArrayToAscii(byteArr, off, len);
            var logMessage = '--------------------\nSent data:\nASCII: ' + asciiData;
            send(logMessage);
        }
        return result;
    };



    // Monitor Network Metrics every second
    setInterval(function() {
        if (CONFIG.networkBytesMetric || CONFIG.networkPacketsMetric) {
            send('--------------------\n' + (CONFIG.networkBytesMetric ? (trackBytes() + '\n') : '') + (CONFIG.networkPacketsMetric ? trackPackets() : ''));
        }
    }, CONFIG.metricPollingInterval);
});

// monitor resource usage - monitor.js
Java.perform(function() {

    // Config
    var CONFIG = {
        // polling interval for metrics in milliseconds
        metricPollingInterval: 1000,
    };



    // CPU Usage
    // Java class for obtaining the PID
    var process = Java.use('android.os.Process');
    // Java class for getting current time (nanoseconds)
    var System = Java.use('java.lang.System');
    // Java class for getting available processors
    var Runtime = Java.use('java.lang.Runtime');
    // Both Java classes used for reading /proc/pid/stat file
    var BufferedReader = Java.use('java.io.BufferedReader');
    var FileReader = Java.use('java.io.FileReader');
    var pid = process.myPid();
    var utime, stime;
    var cpuUsage = 0.0;
    
    var getCPU = function () {
        var reader = null;
        try {
        reader = BufferedReader.$new(FileReader.$new("/proc/" + pid + "/stat"));
        var line = reader.readLine();
        var fields = line.split(" ");
        // utime refers to time spent by cpu to run user level processes
        utime = parseInt(fields[13]);
        // stime refers to time spent by cpu to run system level processes
        stime = parseInt(fields[14]);
        } catch (e) {
        console.error(e);
        } finally {
        if (reader !== null) {
            try {
            reader.close();
            } catch (e) {
            console.error(e);
            }
        }
        }
    };
    
    var updateCPU = function () {
        getCPU();
        var total_time = utime + stime;
        var elapsed_time = System.nanoTime() - startTime;
        cpuUsage = (total_time - prevCpuTime) / (elapsed_time / 1000000) / cpus * 100;
        // prevCPUTime refers to time since last time function was invoked
        prevCpuTime = total_time;
        startTime = System.nanoTime();
    };
    
    var cpus = Runtime.getRuntime().availableProcessors();
    var prevCpuTime = 0;
    var startTime = System.nanoTime();

    var trackCPU = function() {
        updateCPU();
        return('CPU usage: ' + cpuUsage.toFixed(2) + '%');
    };



    // Memory Usage
    function monitorMemoryUsage() {
        var runtime = Runtime.getRuntime();
        var totalMemory = runtime.totalMemory();
        var freeMemory = runtime.freeMemory();
        var usedMemory = totalMemory - freeMemory;
        var memoryUsagePercentage = (usedMemory / totalMemory) * 100;

        return('Total Memory (bytes): ' + totalMemory + '\nFree Memory (bytes): ' + freeMemory + '\nUsed Memory (bytes): ' + usedMemory + '\nMemory Usage (%): ' + memoryUsagePercentage.toFixed(2));
    }



    // Monitor Metrics every second
    setInterval(function() {
        send('--------------------\n' + trackCPU() + '\n' + monitorMemoryUsage());
    }, CONFIG.metricPollingInterval);
});

// permissions - permissions.js
Java.perform(function() {
    // Permission and Malware Score states
    var permissionList = [];
    var malwareScore = '';
    var test = '';
  
    // Declare permission malware scoring mapping
    var permissionMap = {
      "ACCESS_ASSISTED_GPS" :'spyware(location)',
      "ACCESS_CACHE_FILESYSTEM" :'uid',
      "ACCESS_CELL_ID" :'uid',
      "ACCESS_CHECKIN_PROPERTIES" :'uid',
      "ACCESS_COARSE_LOCATION" :'spyware(location)',
      "ACCESS_COARSE_UPDATES" :'uid',
      "ACCESS_DOWNLOAD_MANAGER" :'uid',
      "ACCESS_DOWNLOAD_MANAGER_ADVANCED" :'uid',
      "ACCESS_DRM" :'uid',
      "ACCESS_FINE_LOCATION" :'spyware(location)',
      "ACCESS_GPS" :'spyware(location)',
      "ACCESS_LOCATION" :'spyware(location)',
      "ACCESS_LOCATION_EXTRA_COMMANDS" :'spyware(location)',
      "ACCESS_LOCATTON_MOCK_LOCATION" :'uid',
      "ACCESS_MOCK_LOCATION" :'uid',
      "ACCESS_NETWORK_STATE" :'uid',
      "ACCESS_SURFACE_FLINGER" :'uid',
      "ACCESS_WIFI_STATE" :'uid',
      "ACCESS_WIMAX_STATE" :'uid',
      "ACCOUNT_MANAGER" :'uid',
      "ADD_SYSTEM_SERVICE" :'uid',
      "AUTHENTICATE_ACCOUNTS" :'uid',
      "BACKUP" :'uid',
      "BATTERY_STATS" :'uid',
      "BIND_APPWIDGET" :'uid',
      "BIND_INPUT_METHOD" :'uid',
      "BIND_WALLPAPER" :'uid',
      "BLUETOOTH" :'uid',
      "BLUETOOTH_ADMIN" :'uid',
      "BRICK" :'uid',
      "BROADCAST_PACKAGE_ADDED" :'uid',
      "BROADCAST_PACKAGE_REMOVED" :'uid',
      "BROADCAST_SMS" :'spyware(msg)',
      "BROADCAST_STICKY" :'uid',
      "BROADCAST_WAP_PUSH" :'uid',
      "CALL_PHONE" :'uid',
      "CALL_PRIVILEGED" :'uid',
      "CAMERA" :'spyware(camera)',
      "CHANGE_COMPONENT_ENABLED_STATE" :'uid',
      "CHANGE_CONFIGURATION" :'uid',
      "CHANGE_NETWORK_STATE" :'uid',
      "CHANGE_WIFI_MULTICAST_STATE" :'uid',
      "CHANGE_WIFI_STATE" :'uid',
      "CHANGE_WIMAX_STATE" :'uid',
      "CLEAR_APP_CACHE" :'uid',
      "CLEAR_APP_USER_DATA" :'uid',
      "CONTROL_LOCATION_UPDATES" :'uid',
      "DELETE_CACHE_FILES" :'uid',
      "DELETE_PACKAGES" :'uid',
      "DEVICE_POWER" :'uid',
      "DIAGNOSTIC" :'uid',
      "DISABLE_KEYGUARD" :'uid',
      "DUMP" :'uid',
      "EXPAND_STATUS_BAR" :'uid',
      "FACTORY_TEST" :'uid',
      "FLASHLIGHT" :'uid',
      "FORCE_BACK" :'uid',
      "FORCE_STOP_PACKAGES" :'uid',
      "FULLSCREEN" :'uid',
      "GET_ACCOUNTS" :'uid',
      "GET_PACKAGE_SIZE" :'uid',
      "GET_TASKS" :'uid',
      "GLOBAL_SEARCH" :'uid',
      "GLOBAL_SEARCH_CONTROL" :'uid',
      "HARDWARE_TEST" :'uid',
      "INJECT_EVENTS" :'uid',
      "INSTALL_DRM" :'uid',
      "INSTALL_LOCATION_PROVIDER" :'spyware(location)',
      "INSTALL_PACKAGES" :'dropper',
      "INTERNAL_SYSTEM_WINDOW" :'uid',
      "INTERNET" :'uid',
      "KILL_BACKGROUND_PROCESSES" :'uid',
      "LISTEN_CALL_STATE" :'uid',
      "LOCATION" :'spyware(location)',
      "MANAGE_ACCOUNTS" :'uid',
      "MANAGE_APP_TOKENS" :'uid',
      "MASTER_CLEAR" :'uid',
      "MODIFY_AUDIO_SETTINGS" :'uid',
      "MODIFY_PHONE_STATE" :'uid',
      "MOUNT_FORMAT_FILESYSTEMS" :'uid',
      "MOUNT_UNMOUNT_FILESYSTEMS" :'uid',
      "NEW_OUTGOING_CALL" :'uid',
      "NFC" :'uid',
      "PERMISSION_NAME" :'uid',
      "PERSISTENT_ACTIVITY" :'uid',
      "PROCESS_CALL" :'uid',
      "PROCESS_INCOMING_CALLS" :'uid',
      "PROCESS_OUTGOING_CALLS" :'uid',
      "RAISED_THREAD_PRIORITY" :'uid',
      "READ_CALENDAR" :'uid',
      "READ_CONTACTS" :'uid',
      "READ_EXTERNAL_STORAGE" :'uid',
      "READ_FRAME_BUFFER" :'uid',
      "READ_INPUT_STATE" :'uid',
      "READ_LOGS" :'uid',
      "READ_OWNER_DATA" :'uid',
      "READ_PHONE_STATE" :'uid',
      "READ_SECURE_SETTINGS" :'uid',
      "READ_SETTINGS" :'uid',
      "READ_SMS" :'spyware(msg)',
      "READ_SYNC_SETTINGS" :'uid',
      "READ_USER_DICTIONARY" :'uid',
      "REBOOT" :'uid',
      "RECEIVE_BOOT_COMPLETED" :'uid',
      "RECEIVE_SMS" :'spyware(msg)',
      "RECEIVE_WAP_PUSH" :'uid',
      "RECORD_AUDIO" :'spyware(audio)',
      "RECORD_VIDEO" :'spyware(camera)',
      "REORDER_TASKS" :'uid',
      "RESTART_PACKAGES" :'uid',
      "SEND_DOWNLOAD_COMPLETED_INTENTS" :'uid',
      "SEND_SMS" :'spyware(msg)',
      "SET_ACTIVITY_WATCHER" :'uid',
      "SET_ALWAYS_FINISH" :'uid',
      "SET_ANIMATION_SCALE" :'uid',
      "SET_DEBUG_APP" :'uid',
      "SET_ORIENTATION" :'uid',
      "SET_PREFERRED_APPLICATIONS" :'uid',
      "SET_PROCESS_LIMIT" :'uid',
      "SET_TIME_ZONE" :'uid',
      "SET_WALLPAPER" :'uid',
      "SET_WALLPAPER_COMPONENT" :'uid',
      "SET_WALLPAPER_HINTS" :'uid',
      "SIGNAL_PERSISTENT_PROCESSES" :'uid',
      "STATUS_BAR" :'uid',
      "SUBSCRIBED_FEEDS_READ" :'uid',
      "SUBSCRIBED_FEEDS_WRITE" :'uid',
      "SYSTEM_ALERT_WINDOW" :'ransomware',
      "UPDATE_DEVICE_STATS" :'uid',
      "USE_CREDENTIALS" :'uid',
      "VIBRATE" :'uid',
      "WAKE_LOCK" :'uid',
      "WIFI_LOCK" :'uid',
      "WRITE_APN_SETTINGS" :'uid',
      "WRITE_CALENDAR" :'uid',
      "WRITE_CONTACTS" :'uid',
      "WRITE_EXTERNAL_STORAGE" :'uid',
      "WRITE_GSERVICES" :'uid',
      "WRITE_MEDIA_STORAGE" :'uid',
      "WRITE_OWNER_DATA" :'uid',
      "WRITE_OWNER_FILE" :'uid',
      "WRITE_SECURE" :'uid',
      "WRITE_SECURE_SETTINGS" :'uid',
      "WRITE_SETTINGS" :'uid',
      "WRITE_SMS" :'spyware(msg)',
      "WRITE_SYNC_SETTINGS" :'uid',
      "WRITE_USER_DICTIONARY" :'uid'
      
      
      
        // "MANAGE_DEVICE_POLICY_CAMERA" : 100, // under research
    };
  
  
  
    // Dynamically checks permissions``````
    var checkPermission = function(permission) {
        // Declare android objects
        var ManifestPermission = Java.use('android.Manifest$permission');
        var PackageManagerClass = Java.use('android.content.pm.PackageManager');
        var ProcessClass = Java.use('android.os.Process');
        var context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
        
        /*if (context == null) {
            send('[] Context is null. Unable to check permission.');
            return;
        }*/
  
        var permissionStatus = PackageManagerClass.PERMISSION_DENIED.value;
  
        try {
            permissionStatus = context.checkPermission(ManifestPermission[permission].value, ProcessClass.myPid(), ProcessClass.myUid());
        } catch (e) {
            send('[Permission] Error occurred while checking permission: ' + e);
            //test +='0';
        }
  
        if (permissionStatus === PackageManagerClass.PERMISSION_GRANTED.value) {
            send('[Permission] [+] ' + permission + ' is used in the application.');
            //test +='1,';
            test +='"'+permission+'": [1],';
            // Adds to permission list
            permissionList.push(permission);
        } else {
            send('[Permission] [-] ' + permission + ' is NOT used in the application.');
            //test +='0,';
            test +='"'+permission+'": [0],';
        }
    };
  
  
  
    // Adds to malware score based on permission type
    var malwareScoring = function(permissionList) {
        // Iterates list of permissions to add to malware score
        for (var permission in permissionList) {
            if (permissionList[permission] in permissionMap) {
                malwareScore += permissionMap[permissionList[permission]];
            }
       
        }
  
        //send('[*] Malware score is ' + malwareScore);
        test = test.slice(0,-1);
        send('[Permission.Score] [*] Malware score is ' + test);
        if (malwareScore.includes("spyware(location)")){
            send('[Permission] [*] Location based spyware');}
  
        if (malwareScore.includes("dropper")){
            send('[Permission] [*] Dropper capability');
        }
        if (malwareScore.includes("spyware(camera)")){
            send('[Permission] [*] Camera based spyware');
        }
      
        if (malwareScore.includes("spyware(audio)")){
            send('[Permission] [*] Audio based spyware');
        }
       
        if (malwareScore.includes("spyware(msg)")){
            send('[Permission] [*] Message based spyware');
        }   
        if (malwareScore.includes("ransomware")){
            send('[Permission] [*] Ransomeware capability');
        }
    };
  
    checkPermission("ACCESS_ASSISTED_GPS");
    checkPermission("ACCESS_CACHE_FILESYSTEM");
    checkPermission("ACCESS_CELL_ID");
    checkPermission("ACCESS_CHECKIN_PROPERTIES");
    checkPermission("ACCESS_COARSE_LOCATION");
    checkPermission("ACCESS_COARSE_UPDATES");
    checkPermission("ACCESS_DOWNLOAD_MANAGER");
    checkPermission("ACCESS_DOWNLOAD_MANAGER_ADVANCED");
    checkPermission("ACCESS_DRM");
    checkPermission("ACCESS_FINE_LOCATION");
    checkPermission("ACCESS_GPS");
    checkPermission("ACCESS_LOCATION");
    checkPermission("ACCESS_LOCATION_EXTRA_COMMANDS");
    checkPermission("ACCESS_LOCATTON_MOCK_LOCATION");
    checkPermission("ACCESS_MOCK_LOCATION");
    checkPermission("ACCESS_NETWORK_STATE");
    checkPermission("ACCESS_SURFACE_FLINGER");
    checkPermission("ACCESS_WIFI_STATE");
    checkPermission("ACCESS_WIMAX_STATE");
    checkPermission("ACCOUNT_MANAGER");
    checkPermission("ADD_SYSTEM_SERVICE");
    checkPermission("AUTHENTICATE_ACCOUNTS");
    checkPermission("BACKUP");
    checkPermission("BATTERY_STATS");
    checkPermission("BIND_APPWIDGET");
    checkPermission("BIND_INPUT_METHOD");
    checkPermission("BIND_WALLPAPER");
    checkPermission("BLUETOOTH");
    checkPermission("BLUETOOTH_ADMIN");
    checkPermission("BRICK");
    checkPermission("BROADCAST_PACKAGE_ADDED");
    checkPermission("BROADCAST_PACKAGE_REMOVED");
    checkPermission("BROADCAST_SMS");
    checkPermission("BROADCAST_STICKY");
    checkPermission("BROADCAST_WAP_PUSH");
    checkPermission("CALL_PHONE");
    checkPermission("CALL_PRIVILEGED");
    checkPermission("CAMERA");
    checkPermission("CHANGE_COMPONENT_ENABLED_STATE");
    checkPermission("CHANGE_CONFIGURATION");
    checkPermission("CHANGE_NETWORK_STATE");
    checkPermission("CHANGE_WIFI_MULTICAST_STATE");
    checkPermission("CHANGE_WIFI_STATE");
    checkPermission("CHANGE_WIMAX_STATE");
    checkPermission("CLEAR_APP_CACHE");
    checkPermission("CLEAR_APP_USER_DATA");
    checkPermission("CONTROL_LOCATION_UPDATES");
    checkPermission("DELETE_CACHE_FILES");
    checkPermission("DELETE_PACKAGES");
    checkPermission("DEVICE_POWER");
    checkPermission("DIAGNOSTIC");
    checkPermission("DISABLE_KEYGUARD");
    checkPermission("DUMP");
    checkPermission("EXPAND_STATUS_BAR");
    checkPermission("FACTORY_TEST");
    checkPermission("FLASHLIGHT");
    checkPermission("FORCE_BACK");
    checkPermission("FORCE_STOP_PACKAGES");
    checkPermission("FULLSCREEN");
    checkPermission("GET_ACCOUNTS");
    checkPermission("GET_PACKAGE_SIZE");
    checkPermission("GET_TASKS");
    checkPermission("GLOBAL_SEARCH");
    checkPermission("GLOBAL_SEARCH_CONTROL");
    checkPermission("HARDWARE_TEST");
    checkPermission("INJECT_EVENTS");
    checkPermission("INSTALL_DRM");
    checkPermission("INSTALL_LOCATION_PROVIDER");
    checkPermission("INSTALL_PACKAGES");
    checkPermission("INTERNAL_SYSTEM_WINDOW");
    checkPermission("INTERNET");
    checkPermission("KILL_BACKGROUND_PROCESSES");
    checkPermission("LISTEN_CALL_STATE");
    checkPermission("LOCATION");
    checkPermission("MANAGE_ACCOUNTS");
    checkPermission("MANAGE_APP_TOKENS");
    checkPermission("MASTER_CLEAR");
    checkPermission("MODIFY_AUDIO_SETTINGS");
    checkPermission("MODIFY_PHONE_STATE");
    checkPermission("MOUNT_FORMAT_FILESYSTEMS");
    checkPermission("MOUNT_UNMOUNT_FILESYSTEMS");
    checkPermission("NEW_OUTGOING_CALL");
    checkPermission("NFC");
    checkPermission("PERMISSION_NAME");
    checkPermission("PERSISTENT_ACTIVITY");
    checkPermission("PROCESS_CALL");
    checkPermission("PROCESS_INCOMING_CALLS");
    checkPermission("PROCESS_OUTGOING_CALLS");
    checkPermission("RAISED_THREAD_PRIORITY");
    checkPermission("READ_CALENDAR");
    checkPermission("READ_CONTACTS");
    checkPermission("READ_EXTERNAL_STORAGE");
    checkPermission("READ_FRAME_BUFFER");
    checkPermission("READ_INPUT_STATE");
    checkPermission("READ_LOGS");
    checkPermission("READ_OWNER_DATA");
    checkPermission("READ_PHONE_STATE");
    checkPermission("READ_SECURE_SETTINGS");
    checkPermission("READ_SETTINGS");
    checkPermission("READ_SMS");
    checkPermission("READ_SYNC_SETTINGS");
    checkPermission("READ_USER_DICTIONARY");
    checkPermission("REBOOT");
    checkPermission("RECEIVE_BOOT_COMPLETED");
    checkPermission("RECEIVE_SMS");
    checkPermission("RECEIVE_WAP_PUSH");
    checkPermission("RECORD_AUDIO");
    checkPermission("RECORD_VIDEO");
    checkPermission("REORDER_TASKS");
    checkPermission("RESTART_PACKAGES");
    checkPermission("SEND_DOWNLOAD_COMPLETED_INTENTS");
    checkPermission("SEND_SMS");
    checkPermission("SET_ACTIVITY_WATCHER");
    checkPermission("SET_ALWAYS_FINISH");
    checkPermission("SET_ANIMATION_SCALE");
    checkPermission("SET_DEBUG_APP");
    checkPermission("SET_ORIENTATION");
    checkPermission("SET_PREFERRED_APPLICATIONS");
    checkPermission("SET_PROCESS_LIMIT");
    checkPermission("SET_TIME_ZONE");
    checkPermission("SET_WALLPAPER");
    checkPermission("SET_WALLPAPER_COMPONENT");
    checkPermission("SET_WALLPAPER_HINTS");
    checkPermission("SIGNAL_PERSISTENT_PROCESSES");
    checkPermission("STATUS_BAR");
    checkPermission("SUBSCRIBED_FEEDS_READ");
    checkPermission("SUBSCRIBED_FEEDS_WRITE");
    checkPermission("SYSTEM_ALERT_WINDOW");
    checkPermission("UPDATE_DEVICE_STATS");
    checkPermission("USE_CREDENTIALS");
    checkPermission("VIBRATE");
    checkPermission("WAKE_LOCK");
    checkPermission("WIFI_LOCK");
    checkPermission("WRITE_APN_SETTINGS");
    checkPermission("WRITE_CALENDAR");
    checkPermission("WRITE_CONTACTS");
    checkPermission("WRITE_EXTERNAL_STORAGE");
    checkPermission("WRITE_GSERVICES");
    checkPermission("WRITE_MEDIA_STORAGE");
    checkPermission("WRITE_OWNER_DATA");
    checkPermission("WRITE_OWNER_FILE");
    checkPermission("WRITE_SECURE");
    checkPermission("WRITE_SECURE_SETTINGS");
    checkPermission("WRITE_SETTINGS");
    checkPermission("WRITE_SMS");
    checkPermission("WRITE_SYNC_SETTINGS");
    
    
    
    // Get malware score
    malwareScoring(permissionList);
  });

// root detection bypass - root_bypass.js
Java.perform(function() {
    // Code Adapted from dzonerzy fridantiroot at https://codeshare.frida.re/@dzonerzy/fridantiroot/

    /*
    Original author: Daniele Linguaglossa
    28/07/2021 -    Edited by Simone Quatrini
                    Code amended to correctly run on the latest frida version
                    Added controls to exclude Magisk Manager
    */
    // Print Initalisation
    send('[Initialised] RootDetection Bypass')

    var RootPackages = ["com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
        "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
        "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
        "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
        "eu.chainfire.supersu.pro", "com.kingouser.com", "com.topjohnwu.magisk"
    ];

    var RootBinaries = ["su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk", "magisk"];

    var RootProperties = {
        "ro.build.selinux": "1",
        "ro.debuggable": "0",
        "service.adb.root": "0",
        "ro.secure": "1"
    };

    var RootPropertiesKeys = [];

    for (var k in RootProperties) RootPropertiesKeys.push(k);

    var PackageManager = Java.use("android.app.ApplicationPackageManager");

    var Runtime = Java.use('java.lang.Runtime');

    var NativeFile = Java.use('java.io.File');

    var String = Java.use('java.lang.String');

    var SystemProperties = Java.use('android.os.SystemProperties');

    var BufferedReader = Java.use('java.io.BufferedReader');

    var ProcessBuilder = Java.use('java.lang.ProcessBuilder');

    var StringBuffer = Java.use('java.lang.StringBuffer');

    var loaded_classes = Java.enumerateLoadedClassesSync();

    send("Loaded " + loaded_classes.length + " classes!");

    var useKeyInfo = false;

    var useProcessManager = false;

    //send("loaded: " + loaded_classes.indexOf('java.lang.ProcessManager'));

    if (loaded_classes.indexOf('java.lang.ProcessManager') != -1) {
        try {
            //useProcessManager = true;
            //var ProcessManager = Java.use('java.lang.ProcessManager');
        } catch (err) {
            send("ProcessManager Hook failed: " + err);
        }
    } else {
        send("ProcessManager hook not loaded");
    }

    var KeyInfo = null;

    if (loaded_classes.indexOf('android.security.keystore.KeyInfo') != -1) {
        try {
            //useKeyInfo = true;
            //var KeyInfo = Java.use('android.security.keystore.KeyInfo');
        } catch (err) {
            send("KeyInfo Hook failed: " + err);
        }
    } else {
        send("KeyInfo hook not loaded");
    }



    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pname, flags) {
        var shouldFakePackage = (RootPackages.indexOf(pname) > -1);
        if (shouldFakePackage) {
            send("[RootDetection Bypass] Bypass root check for package: " + pname);
            pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
        }
        return this.getPackageInfo.overload('java.lang.String', 'int').call(this, pname, flags);
    };



    NativeFile.exists.implementation = function() {
        var name = NativeFile.getName.call(this);
        var shouldFakeReturn = (RootBinaries.indexOf(name) > -1);
        if (shouldFakeReturn) {
            send("[RootDetection Bypass] Bypass return value for binary: " + name);
            return false;
        } else {
            return this.exists.call(this);
        }
    };



    var exec = Runtime.exec.overload('[Ljava.lang.String;');
    var exec1 = Runtime.exec.overload('java.lang.String');
    var exec2 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;');
    var exec3 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;');
    var exec4 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File');
    var exec5 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File');

    exec5.implementation = function(cmd, env, dir) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id") {
            var fakeCmd = "grep";
            send("[RootDetection Bypass] Bypass command [" + cmd + "]");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("[RootDetection Bypass] Bypass command [" + cmd + "]");
            return exec1.call(this, fakeCmd);
        }
        if (cmd.includes("ps")) {
            send("[List Processes] Command [" + cmd + "]");
        }
        return exec5.call(this, cmd, env, dir);
    };

    exec4.implementation = function(cmdarr, env, file) {
        for (var i = 0; i < cmdarr.length; i = i + 1) {
            var tmp_cmd = cmdarr[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                var fakeCmd = "grep";
                send("[RootDetection Bypass] Bypass command [" + cmdarr.join(' ') + "]");
                return exec1.call(this, fakeCmd);
            }

            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("[RootDetection Bypass] Bypass command [" + cmdarr.join(' ') + "]");
                return exec1.call(this, fakeCmd);
            }

            if (tmp_cmd.includes("ps")) {
                send("[List Processes] Command [" + cmdarr.join(' ') + "]");
                return exec4.call(this, cmdarr, env, file);
            }
        }
        return exec4.call(this, cmdarr, env, file);
    };

    exec3.implementation = function(cmdarr, envp) {
        for (var i = 0; i < cmdarr.length; i = i + 1) {
            var tmp_cmd = cmdarr[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                var fakeCmd = "grep";
                send("[RootDetection Bypass] Bypass command [" + cmdarr.join(' ') + "]");
                return exec1.call(this, fakeCmd);
            }

            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("[RootDetection Bypass] Bypass command [" + cmdarr.join(' ') + "]");
                return exec1.call(this, fakeCmd);
            }

            if (tmp_cmd.includes("ps")) {
                send("[List Processes] Command [" + cmdarr.join(' ') + "]");
                return exec3.call(this, cmdarr, envp);
            }
        }
        return exec3.call(this, cmdarr, envp);
    };

    exec2.implementation = function(cmd, env) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("[RootDetection Bypass] Bypass command [" + cmd + "]");
            return exec1.call(this, fakeCmd);
        }

        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("[RootDetection Bypass] Bypass command [" + cmd + "]");
            return exec1.call(this, fakeCmd);
        }

        if (cmd.includes("ps")) {
            send("[List Processes] Command [" + cmd + "]");
        }
        return exec2.call(this, cmd, env);
    };

    exec.implementation = function(cmdarr) {
        for (var i = 0; i < cmdarr.length; i = i + 1) {
            var tmp_cmd = cmdarr[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                var fakeCmd = "grep";
                send("[RootDetection Bypass] Bypass command [" + cmdarr.join(' ') + "]");
                return exec1.call(this, fakeCmd);
            }

            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("[RootDetection Bypass] Bypass command [" + cmdarr.join(' ') + "]");
                return exec1.call(this, fakeCmd);
            }

            if (tmp_cmd.includes("ps")) {
                send("[List Processes] Command [" + cmdarr.join(' ') + "]");
                return exec.call(this, cmdarr);
            }
        }

        return exec.call(this, cmdarr);
    };

    exec1.implementation = function(cmd) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id") {
            var fakeCmd = "grep";
            send("[RootDetection Bypass] Bypass command [" + cmd + "]");
            return exec1.call(this, fakeCmd);
        }

        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("[RootDetection Bypass] Bypass command [" + cmd + "]");
            return exec1.call(this, fakeCmd);
        }

        if (cmd.includes("ps")) {
            send("[List Processes] Command [" + cmd + "]");
        }
        return exec1.call(this, cmd);
    };



    String.contains.implementation = function(name) {
        if (name == "test-keys") {
            send("[RootDetection Bypass] Bypass test-keys check");
            return false;
        }
        return this.contains.call(this, name);
    };



    var get = SystemProperties.get.overload('java.lang.String');

    get.implementation = function(name) {
        if (RootPropertiesKeys.indexOf(name) != -1) {
            send("[RootDetection Bypass] Bypass " + name);
            return RootProperties[name];
        }
        return this.get.call(this, name);
    };



    Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
        onEnter: function(args) {
            var path = Memory.readCString(args[0]);
            path = path.split("/");
            var executable = path[path.length - 1];
            var shouldFakeReturn = (RootBinaries.indexOf(executable) > -1)
            if (shouldFakeReturn) {
                Memory.writeUtf8String(args[0], "/notexists");
                send("[RootDetection Bypass] Bypass native fopen");
            }
        },
        onLeave: function(retval) {

        }
    });

    Interceptor.attach(Module.findExportByName("libc.so", "system"), {
        onEnter: function(args) {
            var cmd = Memory.readCString(args[0]);
            send("SYSTEM CMD: " + cmd);
            if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id") {
                send("[RootDetection Bypass] Bypass native system: " + cmd);
                Memory.writeUtf8String(args[0], "grep");
            }
            if (cmd == "su") {
                send("[RootDetection Bypass] Bypass native system: " + cmd);
                Memory.writeUtf8String(args[0], "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled");
            }
        },
        onLeave: function(retval) {

        }
    });

    /*

    TO IMPLEMENT:

    Exec Family

    int execl(const char *path, const char *arg0, ..., const char *argn, (char *)0);
    int execle(const char *path, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
    int execlp(const char *file, const char *arg0, ..., const char *argn, (char *)0);
    int execlpe(const char *file, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
    int execv(const char *path, char *const argv[]);
    int execve(const char *path, char *const argv[], char *const envp[]);
    int execvp(const char *file, char *const argv[]);
    int execvpe(const char *file, char *const argv[], char *const envp[]);

    */


    BufferedReader.readLine.overload('boolean').implementation = function() {
        var text = this.readLine.overload('boolean').call(this);
        if (text === null) {
            // just pass , i know it's ugly as hell but test != null won't work :(
        } else {
            var shouldFakeRead = (text.indexOf("ro.build.tags=test-keys") > -1);
            if (shouldFakeRead) {
                send("[RootDetection Bypass] Bypass build.prop file read");
                text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
            }
        }
        return text;
    };

    var executeCommand = ProcessBuilder.command.overload('java.util.List');

    ProcessBuilder.start.implementation = function() {
        var cmd = this.command.call(this);
        var shouldModifyCommand = false;
        for (var i = 0; i < cmd.size(); i = i + 1) {
            var tmp_cmd = cmd.get(i).toString();
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd.indexOf("mount") != -1 || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd.indexOf("id") != -1) {
                shouldModifyCommand = true;
            }
        }
        if (shouldModifyCommand) {
            send("[RootDetection Bypass] Bypass ProcessBuilder " + cmd);
            this.command.call(this, ["grep"]);
            return this.start.call(this);
        }
        if (cmd.indexOf("su") != -1) {
            send("[RootDetection Bypass] Bypass ProcessBuilder " + cmd);
            this.command.call(this, ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"]);
            return this.start.call(this);
        }

        return this.start.call(this);
    };



    if (useProcessManager) {
        var ProcManExec = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File', 'boolean');
        var ProcManExecVariant = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.lang.String', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'boolean');

        ProcManExec.implementation = function(cmd, env, workdir, redirectstderr) {
            var fake_cmd = cmd;
            for (var i = 0; i < cmd.length; i = i + 1) {
                var tmp_cmd = cmd[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                    var fake_cmd = ["grep"];
                    send("[RootDetection Bypass] Bypass " + cmdarr + " command");
                }

                if (tmp_cmd == "su") {
                    var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                    send("[RootDetection Bypass] Bypass " + cmdarr + " command");
                }
            }
            return ProcManExec.call(this, fake_cmd, env, workdir, redirectstderr);
        };

        ProcManExecVariant.implementation = function(cmd, env, directory, stdin, stdout, stderr, redirect) {
            var fake_cmd = cmd;
            for (var i = 0; i < cmd.length; i = i + 1) {
                var tmp_cmd = cmd[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                    var fake_cmd = ["grep"];
                    send("[RootDetection Bypass] Bypass " + cmdarr + " command");
                }

                if (tmp_cmd == "su") {
                    var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                    send("[RootDetection Bypass] Bypass " + cmdarr + " command");
                }
            }
            return ProcManExecVariant.call(this, fake_cmd, env, directory, stdin, stdout, stderr, redirect);
        };
    }

    if (useKeyInfo) {
        KeyInfo.isInsideSecureHardware.implementation = function() {
            send("[RootDetection Bypass] Bypass isInsideSecureHardware");
            return true;
        }
    }

});