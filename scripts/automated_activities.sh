#!/bin/bash

# start a phone call, wait 10 seconds, hang up the call
adb shell am start -a android.intent.action.CALL -d tel:+19792211000
sleep 10
adb shell input keyevent 6


# write sms, send it, return to home page
adb shell am start -a android.intent.action.SENDTO -d sms:12345678 --es sms_body "hello123"
sleep 2
adb shell input keyevent 61
sleep 1
adb shell input keyevent 66
sleep 2
adb shell input keyevent 3
sleep 2


# create new contact, click on cancel when prompted to sync to google, click on save, return to home page
adb shell am start -a android.intent.action.INSERT -t vnd.android.cursor.dir/contact -e name 'Test' -e phone $(shuf -i 10000000-99999999 -n 1)
sleep 2
adb shell input keyevent 61
sleep 1
adb shell input keyevent 66
sleep 2
adb shell input tap 1328 182
sleep 2
adb shell input keyevent 3
sleep 2


# view contacts list, close contacts application
adb shell input keyevent 207
sleep 2
adb shell am force-stop com.android.contacts
sleep 2


# open camera, allow, next take image, return to home
adb shell am start -a android.media.action.IMAGE_CAPTURE
sleep 2
adb shell input keyevent 61
adb shell input keyevent 61
sleep 1
adb shell input keyevent 66
sleep 2
adb shell input keyevent 61
sleep 1
adb shell input keyevent 66
sleep 2
adb shell input keyevent KEYCODE_CAMERA
sleep 2
adb shell input keyevent 3
sleep 2


# open camera, start recording video, stop recording video, return to home
adb shell am start -a android.media.action.VIDEO_CAPTURE
sleep 2
adb shell input keyevent KEYCODE_CAMERA
sleep 10
adb shell input keyevent KEYCODE_CAMERA
sleep 2
adb shell input keyevent 3
sleep 2


# visit google.com, click accept and continue, click no, click on search bar, type 'youtube', enter, click on youtube   
adb shell am start -a android.intent.action.VIEW -d http://www.google.com
sleep 2
adb shell input keyevent 61
adb shell input keyevent 61
adb shell input keyevent 61
sleep 1
adb shell input keyevent 66
sleep 2
adb shell input keyevent 61
sleep 1
adb shell input keyevent 66
sleep 2
adb shell input keyevent 61
adb shell input keyevent 61
adb shell input keyevent 61
adb shell input keyevent 61
sleep 1
adb shell input keyevent 66
sleep 2
adb shell input text 'youtube'
sleep 1
adb shell input keyevent 66
sleep 2
adb shell input keyevent 61
adb shell input keyevent 61
adb shell input keyevent 61
adb shell input keyevent 61
adb shell input keyevent 61
adb shell input keyevent 61
adb shell input keyevent 61
adb shell input keyevent 61
adb shell input keyevent 61
adb shell input keyevent 61
adb shell input keyevent 61
sleep 1
adb shell input keyevent 66
sleep 10


# fill in simple login form
adb shell am start -a android.intent.action.VIEW -d https://fill.dev/form/login-simple
sleep 2
adb shell input text 'user1'
sleep 2
adb shell input keyevent 61
sleep 2
adb shell input text 'P@ssw0rd'
sleep 2
adb shell input keyevent 61
sleep 1
adb shell input keyevent 66
sleep 2


# fill in simple credit card form
adb shell am start -a android.intent.action.VIEW -d https://fill.dev/form/credit-card-simple
sleep 2
adb shell input text 'user1'
sleep 2
adb shell input keyevent 61
sleep 2
adb shell input keyevent 20
sleep 2
adb shell input keyevent 61
sleep 2
adb shell input text '4321432187658765'
sleep 2
adb shell input keyevent 61
sleep 2
adb shell input text '123'
sleep 2
adb shell input keyevent 61
adb shell input keyevent 61
adb shell input keyevent 61
sleep 1
adb shell input keyevent 66
sleep 2
adb shell input keyevent 3
sleep 2
