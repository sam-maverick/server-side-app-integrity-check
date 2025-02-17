//https://github.com/uuidjs/uuid/issues/514
import 'react-native-get-random-values';
import { v4 as uuidv4 } from 'uuid';

import { Buffer } from 'buffer';
import { Alert } from 'react-native';
import Crypto from 'react-native-quick-crypto';
import { PARAM_PP__CHARSET_AUTH, PARAM_LOGGING_LEVEL } from './update-parameters';
import {LogSys as lsys} from '../src/myGeneralLibrary';
import * as RNQB64 from 'react-native-quick-base64';
//import FileReader from 'react-native-filereader';

const LIBN = '(emclient) (update-utils.js)';


export function LogSys (a,b,c) {
  lsys(a,b,c);
}

export function SafeUrlEncodeForB64 (s) {  // s is supposed to be in base64 format
  //https://stackoverflow.com/questions/1374753/passing-base64-encoded-strings-in-url
  LogSys(LIBN, 0,'SafeUrlEncodeForB64() called');
  const str = String(s);
  retval = str
  .replace(/\+/g,'-')
  .replace(/\//g,'_')
  .replace(/=/g,'.')
  ;
  LogSys(LIBN, 0,'SafeUrlEncodeForB64() finished');
  return retval;
}

export function SafeUrlDecodeForB64 (s) {  //
  LogSys(LIBN, 0,'SafeUrlDecodeForB64() called');
  const str = String(s);
  retval = str
  .replace(/-/g,'+')
  .replace(/_/g,'/')
  .replace(/\./g,'=')
  ;  // reverse URL-safe formatting for base64
  LogSys(LIBN, 0,'SafeUrlDecodeForB64() finished');
  return retval
}

export async function ReadFileAsArrayBuffer(file) {  // Uses browser's FileReader; limited to manual file selection by the end user
  LogSys(LIBN, 1,'ReadFileAsArrayBuffer() called on '+file);

  return new Promise((resolve, reject) => {
      const reader = new FileReader();

      reader.onload = (event) => {
        LogSys(LIBN, 1,'ReadFileAsArrayBuffer() onload event');
        resolve(event.target.result);
      };

      reader.onerror = (err) => {
        LogSys(LIBN, 1,'ReadFileAsArrayBuffer() error event');
        reject(err);
      };

      // ERROR: reader.readAsArrayBuffer() only accepts Blob or File
      // File objects are collected when the user manually selects a file, so it is out of our scope here
      // See: https://developer.mozilla.org/en-US/docs/Web/API/FileReader/readAsDataURL
      reader.readAsArrayBuffer(file);
      LogSys(LIBN, 1,'ReadFileAsArrayBuffer() prepared');

  });
}

export function normalizeEndingSlash(p) {
  if (p != null) {
    return p.replace(/\/*$/, '') + '/';
  }
  return null;
}

export function IsValidImageExtensionAndContentType (myextension) {
    // We assume that there is an equivalence between image extension and image content-type
    if (myextension === null || myextension === undefined) {
      return false;
    }
    return myextension.match(/^[0-9a-zA-Z]+$/);
}

export function EncodeFromB64ToBinary (str) {
    LogSys(LIBN, 0,'EncodeFromB64ToBinary() called');
    retval = Buffer.from(str, 'base64').toString('binary');
    LogSys(LIBN, 0,'EncodeFromB64ToBinary() finished');
    return retval;
}
  
export function EncodeFromBinaryToB64 (str) {
    LogSys(LIBN, 0,'EncodeFromBinaryToB64() called');
    retval = Buffer.from(str, 'binary').toString('base64');
    LogSys(LIBN, 0,'EncodeFromBinaryToB64() finished');
    return retval;
}
  
export function EncodeFromB64ToUTF8 (str) {
    LogSys(LIBN, 0,'EncodeFromB64ToUTF8() called');
    retval = Buffer.from(str, 'base64').toString('utf8');
    LogSys(LIBN, 0,'EncodeFromB64ToUTF8() finished');
    return retval;
}
  
export function EncodeFromUTF8ToB64 (str) {
    LogSys(LIBN, 0,'EncodeFromUTF8ToB64() called');
    retval = Buffer.from(str, 'utf8').toString('base64');
    LogSys(LIBN, 0,'EncodeFromUTF8ToB64() finished');
    return retval;
}

export async function EncodeFromArrayBufferToB64 (ab) {  //*
  LogMe(0,'EncodeFromArrayBufferToB64() called');
  retval = RNQB64.btoa_ab(ab);
  LogMe(0,'EncodeFromArrayBufferToB64() finished');
  return retval;
}

export const AsyncAlert = async (message) => new Promise((resolve) => {
    Alert.alert(
      'Notice',
      message,
      [{
          text: 'Ok',
          onPress: () => {
            resolve('YES');
          },
      },],
      { cancelable: false },
    );
});
  
export function GetRandomIntInclusive(min, max) {
    const randomBuffer = new Uint32Array(1);
  
    Crypto.getRandomValues(randomBuffer);
  
    let randomNumber = randomBuffer[0] / (0xffffffff + 1);
  
    min = Math.ceil(min);
    max = Math.floor(max);
    return Math.floor(randomNumber * (max - min + 1)) + min;
}
  
export function GenerateRandomString (stringLength) {
    let result = '';
    let counter = 0;
    while (counter < stringLength) {
        result += PARAM_PP__CHARSET_AUTH.charAt(GetRandomIntInclusive(0, PARAM_PP__CHARSET_AUTH.length-1));
        counter += 1;
    }
    return result;         
}
  

