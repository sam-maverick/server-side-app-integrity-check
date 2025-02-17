import { PARAM_CHARSET_TOKENS, PARAM_LOGGING_LEVEL } from './parameters';

import * as crypto from "crypto";

const startDate = Date.now();



export async function getSHA256(data: Buffer) {
  const hash = crypto.createHash('sha256');
  hash.update(data);
  return hash.digest();
}

export function FromTimeSpanToHumanReadableMs(lapseMs) {
    const unitspart = Math.floor(lapseMs/1000);
    const decimalpart = lapseMs - unitspart*1000;
    const numofleadingzeros = 3;
    const paddeddecimalpart = "0".repeat(numofleadingzeros).substring(0, numofleadingzeros - decimalpart.toString().length) + decimalpart;
    return (unitspart + '.' + paddeddecimalpart);
  }
  

export function LogMe(level: number, message: string) {
    if (level <= PARAM_LOGGING_LEVEL) {
        let HRspan = FromTimeSpanToHumanReadableMs(Date.now() - startDate);
        const difflen = 3 - HRspan.length;
        if (difflen>0) {
          HRspan = ' '.repeat(difflen) + HRspan;
        }
        console.log(HRspan + ' (ppserver) '+ message);
    }
}

export function EncodeFromB64ToBuffer (str: string) {
    LogMe(1,'EncodeFromB64ToBuffer() called');
    return Buffer.from(str, 'base64');  // Returns a Buffer
}
  
export function EncodeFromBufferToB64 (buff: Buffer) {
    LogMe(1,'EncodeFromBufferToB64() called');
    return buff.toString('base64');  // Returns a String
}

export function EncodeFromB64ToBinary (str: string) {  // Affected by caveat: https://nodejs.org/api/crypto.html#using-strings-as-inputs-to-cryptographic-apis
    LogMe(1,'EncodeFromB64ToBinary() called');
    return Buffer.from(str, 'base64').toString('binary');  // Returns a String
}
  
export function EncodeFromBinaryToB64 (str: string) {
    LogMe(1,'EncodeFromBinaryToB64() called');
    return Buffer.from(str, 'binary').toString('base64');  // Returns a String
}
  


export function GetRandomIntInclusive(min: number, max:number) {
    const randomBuffer = new Uint32Array(1);

    crypto.getRandomValues(randomBuffer);

    let randomNumber = randomBuffer[0] / (0xffffffff + 1);

    min = Math.ceil(min);
    max = Math.floor(max);
    return Math.floor(randomNumber * (max - min + 1)) + min;
}


export function GenerateRandomString (stringLength: number) {
    let result = '';
    let counter = 0;
    while (counter < stringLength) {
        result += PARAM_CHARSET_TOKENS.charAt(GetRandomIntInclusive(0, PARAM_CHARSET_TOKENS.length-1));
        counter += 1;
    }
    return result;          
}


export function isAnInteger(value) {
    return /^\d+$/.test(value);
  }

