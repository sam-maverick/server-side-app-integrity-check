//import { StatusBar } from 'expo-status-bar';

const Buffer = require('buffer').Buffer;

import React, {useState} from 'react';
import { StyleSheet, Button, Text, TextInput, View, SafeAreaView, Alert, Platform } from 'react-native';

import * as FileSystem from 'expo-file-system';
import * as RNQB64 from 'react-native-quick-base64';
import * as base64 from 'base-64';
import * as utf8 from 'utf8'; 
import { Asset } from 'expo-asset';

import { PARAM_LOGGING_LEVEL, PARAM_GOOGLE_CLOUD_PROJECT_NUMBER, PARAM_PP__CRYPTO } from './parameters.js';

import ReactNativeBlobUtil from 'react-native-blob-util';
import { encode } from 'punycode';


// NOTE: When changes are made to files that do not contain components, these changes are not pulled to running apps in real time. You need to re-launch the app to force a re-download.


let LogMeUsername = false;

const MillisDay = 1000 * 60 * 60 * 24;
const MillisHour = 1000 * 60 * 60;
const MillisMinute = 1000 * 60;
const MillisSecond = 1000;

const startDate = Date.now();

export var DebugText = '';



export function FromTimeSpanToHumanReadableString(lapseMs) {
    if (lapseMs >= (MillisDay)) {
        let days = Math.floor(lapseMs/MillisDay);
        let hours = Math.floor((lapseMs-(days*MillisDay))/MillisHour);
        return(days+'d' + (hours>0 ? (hours+'h') : '') );
    } else if (lapseMs >= (MillisHour)) {
        let hours = Math.floor(lapseMs/MillisHour);
        let minutes = Math.floor((lapseMs-(hours*MillisHour))/MillisMinute);
        return(hours+'h' + (minutes>0 ? (minutes+'m') : '') );
    } else if (lapseMs >= (MillisMinute)) {
        let minutes = Math.floor(lapseMs/MillisMinute);
        let seconds = Math.floor((lapseMs-(minutes*MillisMinute))/MillisSecond);
        return(minutes+'m' + (seconds>0 ? (seconds+'s') : '') );
    } else if (lapseMs >= (MillisSecond)) {
        return(Math.floor(lapseMs/MillisSecond)+'s');
    } else {
        return('<1s');
    }  
}

export function FromTimeSpanToHumanReadableMs(lapseMs) {
  const unitspart = Math.floor(lapseMs/1000);
  const decimalpart = lapseMs - unitspart*1000;
  const numofleadingzeros = 3;
  const paddeddecimalpart = "0".repeat(numofleadingzeros).substring(0, numofleadingzeros - decimalpart.toString().length) + decimalpart;
  return (unitspart + '.' + paddeddecimalpart);
}


export async function ToHexString (str) {
  var output;
  for (var i=0; i<str.length; i++) {
    output = output + str.charCodeAt(i) + '-';
    if (i>100) {
      output = output + '!!';
      break;
    }
  }
  return output;
}

export async function ReadMyFileStream (path, mode) {
  LogMe(1,'ReadMyFileStream: Called');
  let data = '';
  const ifstream = await ReactNativeBlobUtil.fs.readStream(
      // file path
      path,
      // encoding, should be one of `base64`, `utf8`, `ascii`
      mode,
      // (optional) buffer size, default to 4096 (4095 for BASE64 encoded data)
      // when reading file in BASE64 encoding, buffer size must be multiples of 3.
      //
      // NOTE: 4095 gives bad performance.
      //
      4096*3*60
  );
  LogMe(1,'ReadMyFileStream: ifstream object created');
  return new Promise((resolve, reject) => {
      ifstream.onError(detail => {
          LogMe(1,'ReadMyFileStream: Error');
          reject(detail);
      });
      ifstream.onEnd(() => {
          LogMe(1,'ReadMyFileStream: Finished reading');
          resolve(data);
      });
      ifstream.open();
      ifstream.onData(chunk => {       
          //LogMe(2,'ReadMyFileStream: Read chunk of data');
          data += chunk;
      });
  });
}



export async function WriteMyFileStream (path, mode, append, data) {
  LogMe(1,'WriteMyFileStream: Called');
  const ofstream = await  ReactNativeBlobUtil.fs.writeStream(
    path,
    // encoding, should be one of `base64`, `utf8`, `ascii`
    mode,
    // should data append to existing content ?
    append
  );
  LogMe(1,'WriteMyFileStream: ofstream object created');
  return new Promise((resolve, reject) => {
    LogMe(1,'WriteMyFileStream: Writing');          
    ofstream.write(data)
    .then(ofstream => {
      LogMe(1,'WriteMyFileStream: Closing');      
      ofstream.close()
      .then(() => {
        LogMe(1,'WriteMyFileStream: Resolving');      
        resolve();
      })
      .catch(detail => {
        LogMe(1,'ReadMyFileStream: Error');
        reject(detail);
      });
    })
    .catch(detail => {
      LogMe(1,'ReadMyFileStream: Error');
      reject(detail);
    });
  });
}


export function SafeUrlEncodeForB64 (s) {  // s is supposed to be in base64 format
  //Inspired in: https://stackoverflow.com/questions/1374753/passing-base64-encoded-strings-in-url
  LogMe(0,'SafeUrlEncodeForB64() called');
  const str = String(s);
  retval = str
  .replace(/\+/g,'-')
  .replace(/\//g,'_')
  .replace(/=/g,'.')
  ;
  LogMe(0,'SafeUrlEncodeForB64() finished');
  return retval;
}

export function SafeUrlDecodeForB64 (s) {  //
  LogMe(0,'SafeUrlDecodeForB64() called');
  const str = String(s);
  retval = str
  .replace(/-/g,'+')
  .replace(/_/g,'/')
  .replace(/\./g,'=')
  ;  // reverse URL-safe formatting for base64
  LogMe(0,'SafeUrlDecodeForB64() finished');
  return retval;
}


export async function EncodeFromB64ToBuffer (str) {
  LogMe(0,'EncodeFromB64ToBuffer() called');
  retval = Buffer.from(str, 'base64');
  LogMe(0,'EncodeFromB64ToBuffer() finished');
  return retval;  // Returns a Buffer
}

export async function EncodeFromBufferToB64 (buff) {
  LogMe(0,'EncodeFromBufferToB64() called');
  retval = buff.toString('base64');
  LogMe(0,'EncodeFromBufferToB64() finished');
  return retval;
}

export async function EncodeFromStringToB64 (str) {  //*
  LogMe(0,'EncodeFromStringToB64() called');
  retval = RNQB64.btoa(str);
  LogMe(0,'EncodeFromStringToB64() finished');
  return retval;
}

export async function EncodeFromArrayBufferToB64 (ab) {  //*
  LogMe(0,'EncodeFromArrayBufferToB64() called');
  retval = RNQB64.btoa_ab(ab);
  LogMe(0,'EncodeFromArrayBufferToB64() finished');
  return retval;
}

export async function EncodeFromB64ToBinary (str) {  // Affected by caveat: https://nodejs.org/api/crypto.html#using-strings-as-inputs-to-cryptographic-apis
  LogMe(0,'EncodeFromB64ToBinary() called');
  /*
  return Buffer.from(str, 'base64').toString('binary');  // Returns a String
  */
  retval = await base64.decode(str);
  LogMe(0,'EncodeFromB64ToBinary() finished');
  return retval;
}

export async function EncodeFromBinaryToB64 (str) {
  LogMe(0,'EncodeFromBinaryToB64() called');
  /*
  LogMe(1,'EncodeFromBinaryToB64(): buffering');
  const buffervalue = Buffer.from(str, 'binary');
  LogMe(1,'EncodeFromBinaryToB64(): toString');
  return buffervalue.toString('base64');  // Returns a String
  */
  retval = await base64.encode(str);
  LogMe(0,'EncodeFromBinaryToB64() finished');
  return retval;
  // Don't do that - it doesn't work!
  //return str.toString('base64');  // Returns a String
}

export async function EncodeFromFullrangeBinaryToB64 (str) {
  LogMe(0,'EncodeFromFullrangeBinaryToB64() called');
  LogMe(1,'EncodeFromFullrangeBinaryToB64(): buffering');
  const buffervalue = Buffer.from(str, 'binary');
  LogMe(1,'EncodeFromFullrangeBinaryToB64(): toString');
  const retval = buffervalue.toString('base64')
  LogMe(0,'EncodeFromFullrangeBinaryToB64() finished');
  return retval;  // Returns a String
  // Don't do that - it doesn't work!
  //return str.toString('base64');  // Returns a String
}

export async function EncodeFromB64ToUTF8 (str) {
  LogMe(0,'EncodeFromB64ToUTF8() called');
  retval = Buffer.from(str, 'base64').toString('utf8');
  LogMe(0,'EncodeFromB64ToUTF8() finished');
  return retval;  // Returns a String
}

export async function EncodeFromUTF8ToB64 (str) {
  LogMe(0,'EncodeFromUTF8ToB64() called');
  retval = Buffer.from(str, 'utf8').toString('base64');
  LogMe(0,'EncodeFromUTF8ToB64() finished');
  return retval;  // Returns a String
}



export function UpdateLogMeUsername (theusername) {
    LogMeUsername = theusername;
}

export function ClearDebugText() {
  DebugText = '';
}

export function LogMe(level, message) {
    if (level <= PARAM_LOGGING_LEVEL) {
        let usernameHeader = '';
        if (! LogMeUsername === false) {
            usernameHeader = '['+LogMeUsername+']: ';
        }
        let HRspan = FromTimeSpanToHumanReadableMs(Date.now() - startDate);
        const difflen = 3 - HRspan.length;
        if (difflen>0) {
          HRspan = ' '.repeat(difflen) + HRspan;
        }
        console.log(HRspan + ' (ppclient) '+usernameHeader + message);
        DebugText = DebugText + HRspan + '\t' + '(ppclient) ' + message + '\n';
    }
}

export function LogSys(libname, level, message) {
  LogMe (level, libname+' '+message);
}

export const AsyncAlert = async (message, title) => new Promise((resolve) => {
    Alert.alert(
      title,
      message,
      [
        {
          text: 'Ok',
          onPress: () => {
            resolve('YES');
          },
        },
      ],
      { cancelable: false },
    );
});

export const AsyncAlertReport = async (message, title) => new Promise((resolve) => {
  Alert.alert(
    title,
    message,
    [
      {
        text: 'Report',
        style: 'destructive',  // Only has effect in iOS
        onPress: () => {
          resolve('REPORT');
        },
      },
      {
        text: 'Ok',
        onPress: () => {
          resolve('YES');
        },
      },
    ],
    { cancelable: false },
  );
});

export async function ErrorAlertAsync(message, errorObject) {
    LogMe(1, '* * * * * * ERROR * * * * * *  ' + message);
    if (errorObject!=undefined) { LogMe(1, errorObject.stack); }
    let finalmessage = message;
    if (errorObject!=undefined) { finalmessage = message + '\n' + errorObject.message }

    return await AsyncAlert(message, 'Error');
}


export async function ErrorAlertAsyncReport(message, errorObject, title) {
  LogMe(1, '* * * * * * ERROR * * * * * *  ' + message);
  if (errorObject!=undefined) { LogMe(1, errorObject.stack); }
  let finalmessage = message;
  if (errorObject!=undefined) { finalmessage = message + '\n' + errorObject.message }

  return await AsyncAlertReport(message, title);
}


export function ErrorAlert(message, errorObject) {
    LogMe(1, '* * * * * * ERROR * * * * * *  ' + message);
    if (errorObject!=undefined) { LogMe(1, errorObject.stack); }
    let finalmessage = message;
    if (errorObject!=undefined) { finalmessage = message + '\n' + errorObject.message }

    Alert.alert(
      'Error',
      finalmessage,
      [
        { text: 'Ok' },
      ],
      { cancelable: false }
    );
}



export function InfoMessage(title, message) {
    LogMe(2, 'INFO provided to the user: ' + title + ': ' + message);
    Alert.alert(
      title,
      message,
      [
        { text: 'Ok' },
      ],
      { cancelable: false }
    );
}

export async function InitialisationActions() {
    LogMe(1, 'InitialisationActions()');

    LogMeUsername = false;

    if (PARAM_PP__CRYPTO.null_crypto) {
      LogMe(1, 'Show warning about null_crypto');
      await AsyncAlert('PARAM_PP__CRYPTO.null_crypto is enabled. This means that the private pictures will not be encrypted!', 'WARNING');
    }      
    
}


export function IsValidImageExtensionAndContentType (myextension) {
    // We assume that there is an equivalence between image extension and image content-type
    return myextension.match(/^[0-9a-zA-Z]+$/);
}


export async function LoadBaseImageAssetFileB64() {
  // Asset class requires `npx expo install expo-asset'
  // Do not change localUri symbol here
  //const contents1 = await FileSystem.readAsStringAsync('./myGeneralLibrary.jsx', {encoding: 'base64'});
  //LogMe(1,'GetPngBaseImageForWrapping(): Done');

  // WARNING .-
  // Referencing Assets in Image components works fine in all cases.
  // Reading Asset files works just fine with the bare workflow on metro, but it doesn't work with the production build of APK/AAB.
  // Therefore, the code below does not work

  /*
  const myAsset = Asset.fromModule(require('../assets/custom/base_image_for_wrapping.png'));  // the 'require' syntax does not accept variables

  LogMe(1,'GetPngBaseImageForWrapping(): myAsset, before downloadAsync ======'+JSON.stringify(myAsset));
  if (!myAsset.localUri) {
    LogMe(1,'GetPngBaseImageForWrapping(): performing downloadAsync() on myAsset');
    await myAsset.downloadAsync();
  }
  LogMe(1,'GetPngBaseImageForWrapping(): myAsset, after downloadAsync ======'+JSON.stringify(myAsset));

  const contents = await FileSystem.readAsStringAsync(myAsset.localUri, {encoding: 'base64'});
  LogMe(2,'GetPngBaseImageForWrapping(): contents ======'+JSON.stringify(contents));
  return contents;
  */
}

