# react-native-sodium-boa

Precompiled binaries of [libsodium](https://libsodium.org) will be linked by default.
Optionally, you can choose to compile libsodium by yourself (run __npm&nbsp;run&nbsp;rebuild__ in package directory). Source code will be downloaded and verified before compilation.

### Source compilation
###### MacOS prerequisites
* libtool (macports, homebrew)
* autoconf (macports, homebrew)
* automake (macports, homebrew)


###### Android prerequisites
* Android NDK
* CMake
* LLDB

### Usage

1. npm install react-native-sodium-boa --save
2. npx pod-install
3. npx react-native run-ios | run-android

### Help
See [example application](https://github.com/bosagora/react-native-sodium-boa-example).
