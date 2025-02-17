const Buffer = require('buffer').Buffer;

import { Platform } from 'react-native';

import Crypto from 'react-native-quick-crypto';

var png = require('png-metadata');


import { 
    EncodeFromB64ToBuffer, 
    EncodeFromBufferToB64, 
    EncodeFromStringToB64,
    EncodeFromArrayBufferToB64,
    EncodeFromB64ToBinary, 
    EncodeFromBinaryToB64, 
    EncodeFromB64ToUTF8,
    EncodeFromUTF8ToB64,
    ErrorAlert, 
    ErrorAlertAsync, 
    AsyncAlert, 
    LogMe, 
 } from '../myGeneralLibrary.jsx';

import {
  PARAM_PP__CRYPTO,
  PARAM_GOOGLE_CLOUD_PROJECT_NUMBER,
  PARAM_IMPLEMENTATION_OPTION_B64,
  PARAM_IMPLEMENTATION_OPTION_PNG,
  PARAM_IMPLEMENTATION_ARTIFACT_FORMAT,
  PP_PLATFORM_NICKNAME,
  PARAM_PP__MAX_WARMUP_INTERVAL_MS,
} from '../parameters.js';

import { ApiGetNonceFromServer, ApiSubmitAttestationTokensToServer } from '../network/networkApi.js';

import * as AppIntegrity from '../integrity/integrityapis.js';


var lastWarmup = 0;


// We assume that Platform.OS has already been checked to be compatible
export async function RequestToDecryptThings(myPPEcookie, iosKeyName, requestDataObject) {
  LogMe(0, 'RequestToDecryptThings() called');
  LogMe(2, 'requestDataObject:'+JSON.stringify(requestDataObject));
  LogMe(0, 'Requesting token(s) from server');

  // GET NONCE(S)

  let apiresgetnonce1 = undefined;        
  //#*#let apiresgetnonce2 = undefined;        
  try {

    /**
     * Getting the nonce from the server also acts as a server connection test. If it fails, it will propagate the error, 
     * and no warmup/attestation/assertion operations will be performed. Note that we request the nonce *before* the warmup, 
     * in Android. This is necessary to avoid increasing security metrics when a user repeatedly attempts to open a private
     * picture when there are network issues, as this could potentially cause false positives.
     */

    if (Platform.OS === 'android') {
      
      LogMe(0, 'Obtaining nonce from server');
      apiresgetnonce1 = await ApiGetNonceFromServer(myPPEcookie, 'android', 'standard');
      LogMe(0, 'Nonce obtained');
      //#*#apiresgetnonce2 = await ApiGetNonceFromServer(myPPEcookie, 'android', 'classic');

      // Check if we have to refresh the attestation cache;
      // otherwise the PP server will give a 'request too old' if our attestation is not fresh enough.
      if (lastWarmup==0 || (Date.now()-lastWarmup) > PARAM_PP__MAX_WARMUP_INTERVAL_MS) {
        LogMe(0, 'Doing Android warmup');
        await AppIntegrity.DoWarmup(function () {}, function () {});
        lastWarmup = Date.now();
        LogMe(0, 'Android warmup done');
      } else {
        LogMe(1, 'Skipping Android warmup; it was already done before');
      }

    } else {  // ios
      LogMe(0, 'Obtaining nonce from server');
      apiresgetnonce1 = await ApiGetNonceFromServer(myPPEcookie, 'ios', 'assertion');
      LogMe(0, 'Nonce obtained');
    }
  } catch(error) {
      const msg = 'Error when requesting nonce to the PP server or when warming up. ';
      LogMe(1, msg + error.stack);  // Network error
      return Promise.reject({message: msg + error.message});
  }

  LogMe(1, 'Checking for server-side application errors');
  // Check for server-side application errors
  if (Platform.OS === 'android') {
    if ( ! apiresgetnonce1.isSuccessful) {
      const msg = 'Application error when requesting android-standard nonce to the PP server. ';
      LogMe(1, msg + apiresgetnonce1.resultMessage);
      return Promise.reject({message: msg + apiresgetnonce1.resultMessage});
    }
    //#*#if ( ! apiresgetnonce2.isSuccessful) {
    //#*#  const msg = 'Application error when requesting android-classic nonce to the PP server. ';
    //#*#  LogMe(1, msg + apiresgetnonce2.resultMessage);
    //#*#  return Promise.reject({message: msg + apiresgetnonce2.resultMessage});
    //#*#}
  } else {  // ios
    if ( ! apiresgetnonce1.isSuccessful) {
      const msg = 'Application error when requesting ios-assertion nonce to the PP server. ';
      LogMe(1,  + apiresgetnonce1.resultMessage);
      return Promise.reject({message: msg + apiresgetnonce1.resultMessage});
    }
  }

  LogMe(1, 'Creating attestation token object(s)');
                   
  // GET TOKEN(S) FROM ATTESTATION API

  let attestationobject1 = undefined;
  //#*#let attestationobject2 = undefined;

  if (Platform.OS === 'android') {
    try {
      LogMe(0, 'Obtaining attestation token from API');
      attestationobject1 = await AppIntegrity.AndroidStandardRequest(apiresgetnonce1.nonce, PARAM_GOOGLE_CLOUD_PROJECT_NUMBER.toString());
      LogMe(0, 'Attestation token obtained');
    } catch(error) {
      return Promise.reject({message: 'Coult not prepare Android Standard attestation object. Error from AppIntegrity API.\n'+JSON.stringify(error)});
    }  
    //#*#try {
    //#*#  attestationobject2 = await AppIntegrity.AndroidClassicRequest(apiresgetnonce2.nonce, PARAM_GOOGLE_CLOUD_PROJECT_NUMBER);
    //#*#} catch(error) {
    //#*#  return Promise.reject({message: 'Coult not prepare Android Classic attestation object. Error from AppIntegrity API.\n'+JSON.stringify(error)});
    //#*#}
  } else {  // ios
    // We skip attestation because we can assume it has been done, as the device needs to achieve enrollment to reach this point
    try {
      LogMe(0, 'Obtaining assertion token from API');
      attestationobject1 = await AppIntegrity.iosAppAssertRequest(iosKeyName, apiresgetnonce1.nonce);
      LogMe(0, 'Assertion token obtained');
    } catch(error) {
      return Promise.reject({message: 'Coult not prepare iOS assertion object. Error from AppIntegrity API.\n'+JSON.stringify(error)});
    }          
  }

  // SUBMIT TOKEN(S) TO OUR PP SERVER

  LogMe(0, 'Submitting token(s) to PP server');
  LogMe(1, 'cookie:'+myPPEcookie);

  let apiressubmitobject = undefined;

  try {
    if (Platform.OS === 'android') {
      apiressubmitobject = await ApiSubmitAttestationTokensToServer(
        'PPWrapOps', 
        myPPEcookie, 
        Platform.OS, 
        Platform.Version, 
        [
          {
            requestType: 'standard',
            token: attestationobject1,
            keyId: iosKeyName,
          },
          //#*#{
          //#*#  requestType: 'classic',
          //#*#  token: attestationobject2,
          //#*#},
        ],
        requestDataObject,
      );
    } else {  // ios
      apiressubmitobject = await ApiSubmitAttestationTokensToServer(
        'PPWrapOps', 
        myPPEcookie, 
        Platform.OS, 
        Platform.Version, 
        [
          {
            requestType: 'assertion',
            token: attestationobject1,
          },
        ],
        requestDataObject,
      );
    }
  } catch(error) {  // Network error
    const msg = 'Error when submitting attestation token to the PP server. ';
    LogMe(1, msg + error.stack);
    return Promise.reject({message: msg+error.message});
  }          

  // CHECK RESULT GIVEN BY THE PP SERVER

  LogMe(1, 'Checking response from PP server');

  if ( ! apiressubmitobject.isSuccessful) {
    // Failed by application (attestation rejected)
    const msg = '' + apiressubmitobject.resultMessage;
    LogMe(1, msg);
    return Promise.reject({message: msg, pictureID: apiressubmitobject?.pictureID});
  } else {
      // Successful
      return Promise.resolve(apiressubmitobject);
  }

}



// wrappedPicture is an enveloppe containing a private picture, in base64 formatted String
// It returns an object
// In case of error/failure, it throws an Error. It is up to the calling code to catch it.
export async function UnwrapPicture (wrappedPictureObject, myAccountData) {
  LogMe(0, 'UnwrapPicture() called');

  // Unwrap (steganographically)

  let ppPpChunkFound = false;
  let ppPpChunkContents = {};

  LogMe(0, 'Parsing PNG metadata');
  let list = await ( async () => {
    switch ( PARAM_IMPLEMENTATION_OPTION_PNG ) {
      case 's': 
        LogMe(1, 'Parsing PNG metadata: decoding from B64 to Binary string');
        const s = await EncodeFromB64ToBinary(wrappedPictureObject);
        LogMe(1, 'Parsing PNG metadata: splitChunk');
        return await png.splitChunk(s);
      case 'b':
        LogMe(1, 'Parsing PNG metadata: decoding from B64 to Buffer');
        const b = await EncodeFromB64ToBuffer(wrappedPictureObject);
        LogMe(1, 'Parsing PNG metadata: splitChunk');
        return await png.splitChunkBufferTyped(b);
      default:
        throw new Error('Bug. Invalid PARAM_IMPLEMENTATION_OPTION_PNG: ' + PARAM_IMPLEMENTATION_OPTION_PNG);
    }
  } )();
  
  LogMe(2, 'Metadata contents:'+JSON.stringify(list))

  LogMe(1, 'Checking if there is ppPp chunk');
  await list.forEach(function (arrayItem) {
      const isThis_a_ppPp_chunk = ( () => {
        if ( ! arrayItem?.type) {
          return false;
        }
        switch ( PARAM_IMPLEMENTATION_OPTION_PNG ) {
          case 's': 
            return arrayItem.type === 'ppPp';
          case 'b':
            return arrayItem.type.equals(Buffer.from('ppPp', 'binary'));
          default:
            throw new Error('Bug. Invalid PARAM_IMPLEMENTATION_OPTION_PNG: ' + PARAM_IMPLEMENTATION_OPTION_PNG);
        }
      } )();

      if (isThis_a_ppPp_chunk && arrayItem?.data) {
          LogMe(1, 'Found ppPp chunk with data');
          ppPpChunkFound = true;
          ppPpChunkContents = JSON.parse(arrayItem.data);
      }
  });
  
  if (!ppPpChunkFound) {
    throw new Error('ppPp chunk was not found or it did not contain data');
  } else {

    LogMe(0, 'Metadata from PNG extracted');

    // Unwrap cryptographically

    // We assume that the device is already enrolled (it must be checked and it is checked by PPWrapOps.jsx)
    // In any case, in practice, server response will give a FAIL if not enrolled

    let returnObject = {};

    if (ppPpChunkContents.null_crypto) {
      returnObject = {
        data: ppPpChunkContents.data,
        contentType: ppPpChunkContents.contentType,
        privacyPolicies: ppPpChunkContents.privacyPolicies, 
      };
    } else {
      // STAGE3 & STAGE2

      // Make request to the PP server to decrypt stuff
      let replyObjectFromServer = await RequestToDecryptThings(
        myAccountData.PPEcookie,
        myAccountData.iosKeyName,
        {
          stage2: {
            encrypted_stage2_key_b64: ppPpChunkContents.stage2.encrypted_stage2_key_b64,
            iv_b64: ppPpChunkContents.stage2.iv_b64, 
            encryption_algorithm: ppPpChunkContents.stage2.encryption_algorithm, 
          },
          stage1: {
            encrypted_stage1_key_and_params_b64: ppPpChunkContents.stage1.encrypted_stage1_key_and_params_b64,
            ciphertext_to_server_data: ppPpChunkContents.stage1.ciphertext_to_server_data,
          },
        },
      );

      LogMe(2, 'replyDataObjectFromServer: '+JSON.stringify(replyObjectFromServer));

      //STAGE1
      LogMe(0, 'UnwrapPicture(): STAGE1');
      /*
      // Since the key is not a human password but random bits, we do not need to pbkdfify
      const pbkdf_algorithm = await EncodeFromB64ToBinary(ppPpChunkContents.stage1.pbkdf_algorithm).toString();
      const pbkdf_iterations = Number(await EncodeFromB64ToBinary(ppPpChunkContents.stage1.pbkdf_iterations));
      const password = ...
      const salt = ...
      const key = Crypto.pbkdf2Sync(password, salt, pbkdf_iterations, 32, pbkdf_algorithm);
      */
      LogMe(0, 'UnwrapPicture(): STAGE1: creating createDecipheriv');
      const cipher1 = Crypto.createDecipheriv(
        replyObjectFromServer.replyDataObject.stage1.encryption_algorithm, 
        await EncodeFromB64ToBuffer(replyObjectFromServer.replyDataObject.stage1.key_b64), 
        await EncodeFromB64ToBuffer(replyObjectFromServer.replyDataObject.stage1.iv_b64)
      );
      LogMe(0, 'UnwrapPicture(): STAGE1: createDecipheriv created');
      LogMe(0, 'UnwrapPicture(): STAGE1: writing');
      await cipher1.write(await EncodeFromB64ToBuffer(ppPpChunkContents.ciphertext));
      LogMe(0, 'UnwrapPicture(): STAGE1: written');
      await cipher1.end();
      LogMe(0, 'UnwrapPicture(): STAGE1: reading');
      const decrypted_picture = await cipher1.read();
      LogMe(0, 'UnwrapPicture(): STAGE1: read');

      // Return the results
      returnObject = {
        'contentType': ppPpChunkContents.contentType,
        'data': decrypted_picture,
        'privacyPolicies': replyObjectFromServer.replyDataObject.privacyPolicies,
        'pictureId': replyObjectFromServer.replyDataObject.pictureId,
      };

      LogMe(1, "UnwrapPicture(): privacyPolicies: "+JSON.stringify(returnObject.privacyPolicies));
      LogMe(1, "UnwrapPicture(): pictureId: "+returnObject.pictureId);

      replyObjectFromServer = undefined;

    }

    gc();  // Call garbage collector

    LogMe(0, 'UnwrapPicture(): Finished');
    return returnObject;
  }
}




// plainPicture is a picture content in base64 formatted String
// It returns a base64 formatted String
export async function WrapPicture (plainPicture, fileExt, myAccountData, privacyPoliciesObj) {
    LogMe(0, 'WrapPicture() called');

    // Wrap cryptographically

    let ppPlainPictureObjectStr = '';

    if (PARAM_PP__CRYPTO.null_crypto) {
      ppPlainPictureObjectStr = JSON.stringify({
        'null_crypto': true,
        'data': plainPicture, 
        'contentType': fileExt,
        'privacyPolicies': privacyPoliciesObj, 
      });  
    } else {
      // STAGE1
      LogMe(0, 'WrapPicture(): STAGE1');
      /*
      // Since the key is not a human password but random bits, we do not need to pbkdfify
      const pbkdf_algorithm = PARAM_PP__CRYPTO.stage1.pbkdf_algorithm;
      const pbkdf_iterations = PARAM_PP__CRYPTO.stage1.pbkdf_iterations;
      const password = Crypto.randomBytes(32);
      const salt = Crypto.randomBytes(16);
      const key = Crypto.pbkdf2Sync(password, salt, pbkdf_iterations, 32, pbkdf_algorithm);
      */
      const stage1_key = Crypto.randomBytes(32);
      const stage1_iv = Crypto.randomBytes(16);
      LogMe(0, 'UnwrapPicture(): STAGE1: creating createCipheriv');
      const cipher1 = Crypto.createCipheriv(PARAM_PP__CRYPTO.stage1.encryption_algorithm, stage1_key, stage1_iv);
      LogMe(0, 'UnwrapPicture(): STAGE1: createCipheriv created');
      LogMe(0, 'WrapPicture(): STAGE1: writing');
      await cipher1.write(plainPicture);
      LogMe(0, 'WrapPicture(): STAGE1: written');
      await cipher1.end();
      LogMe(0, 'WrapPicture(): STAGE1: reading');
      const ciphertext_picture = await cipher1.read();
      LogMe(0, 'WrapPicture(): STAGE1: read');
 
      // STAGE2
      LogMe(1, 'WrapPicture(): STAGE2');
      const stage2_key = Crypto.randomBytes(32);
      const stage2_iv = Crypto.randomBytes(16);
      LogMe(0, 'UnwrapPicture(): STAGE2: creating createCipheriv');
      const cipher2 = Crypto.createCipheriv(PARAM_PP__CRYPTO.stage2.encryption_algorithm, stage2_key, stage2_iv);
      LogMe(0, 'UnwrapPicture(): STAGE2: createCipheriv created');
      LogMe(0, 'WrapPicture(): STAGE2: writing');
      await cipher2.write(JSON.stringify({
        encryption_algorithm: PARAM_PP__CRYPTO.stage1.encryption_algorithm,
        iv_b64: await EncodeFromArrayBufferToB64(stage1_iv.buffer),
        key_b64: await EncodeFromArrayBufferToB64(stage1_key.buffer),
      }));  // stage1 data
      LogMe(0, 'WrapPicture(): STAGE2: written');
      await cipher2.end();
      LogMe(0, 'WrapPicture(): STAGE2: reading');
      const ciphertext_stage1 = await cipher2.read();
      LogMe(0, 'WrapPicture(): STAGE2: read');

      const myPictureId = Crypto.randomBytes(32);
      const myPictureIdSenderPrivate = Crypto.randomBytes(32);
      LogMe(0, 'UnwrapPicture(): STAGE2b: creating createCipheriv');
      const cipher2b = Crypto.createCipheriv(PARAM_PP__CRYPTO.stage2.encryption_algorithm, stage2_key, stage2_iv);
      LogMe(0, 'UnwrapPicture(): STAGE2b: createCipheriv created');
      LogMe(0, 'WrapPicture(): STAGE2b: writing');
      await cipher2b.write(JSON.stringify({
        privacyPolicies: privacyPoliciesObj,
        pictureId: await EncodeFromArrayBufferToB64(myPictureId.buffer),
        pictureIdSenderPrivate: await EncodeFromArrayBufferToB64(myPictureIdSenderPrivate.buffer),  // This must be kept secret from the recipient
      }));
      LogMe(0, 'WrapPicture(): STAGE2b: written');
      await cipher2b.end();
      LogMe(0, 'WrapPicture(): STAGE2b: reading');
      const ciphertext_to_server_data = await cipher2b.read();
      LogMe(0, 'WrapPicture(): STAGE2b: read');
      LogMe(1, 'Encoded pictureId=' + await EncodeFromArrayBufferToB64(myPictureId.buffer));
      LogMe(1, 'Encoded pictureIdSenderPrivate=' + await EncodeFromArrayBufferToB64(myPictureIdSenderPrivate.buffer));

      // STAGE3
      LogMe(1, 'WrapPicture(): STAGE3');
      const provider_pubkey = await EncodeFromB64ToBinary(require('../../bundled_files/json/rsa-pubkey-wrapping-ppclient.pem.json').data);

      LogMe(0, 'WrapPicture(): STAGE3: publicEncrypt-ing');
      const encrypted_stage2_key = Crypto.publicEncrypt(
        Buffer.from(provider_pubkey), 
        stage2_key
      );
      LogMe(0, 'WrapPicture(): STAGE3: publicEncrypt-ed');

      // Pack contents

      LogMe(1, 'WrapPicture(): ciphertext_picture_B64 start B64 encoding, length in bytes='+ciphertext_picture.length);
      const ciphertext_picture_B64 = await EncodeFromArrayBufferToB64(ciphertext_picture.buffer);
      LogMe(1, 'WrapPicture(): ciphertext_picture_B64 end B64 encoding');

      LogMe(1, 'WrapPicture(): Creating metadata object');
      ppPlainPictureObjectStr = JSON.stringify({
        null_crypto: false,
        stage1: {
          encrypted_stage1_key_and_params_b64: await EncodeFromArrayBufferToB64(ciphertext_stage1.buffer),
          ciphertext_to_server_data: await EncodeFromArrayBufferToB64(ciphertext_to_server_data.buffer),  // privacy policies will go here
        },
        stage2: {
          encryption_algorithm: PARAM_PP__CRYPTO.stage2.encryption_algorithm,
          iv_b64: await EncodeFromArrayBufferToB64(stage2_iv.buffer),
          encrypted_stage2_key_b64: await EncodeFromArrayBufferToB64(encrypted_stage2_key.buffer),
        }, 
        stage3: {
          provider: 'someprovider',
          encryption_algorithm: PARAM_PP__CRYPTO.stage3.encryption_algorithm,
        }, 
        ciphertext: ciphertext_picture_B64, 
        contentType: fileExt,
        // We can put the privacy policies also in the clear, here, for informational purposes. Our algorithms are CPA-secure.
        // This can be used in the recipient's GUI of the messging app to show information about the expiration date of the picture, etc.
        privacyPoliciesInfo: privacyPoliciesObj,
      });  
    }
    LogMe(1, 'WrapPicture(): Created metadata object');

    // Wrap inside a picture (steganographically)

    // WARNING .-
    // Referencing Assets in Image components works fine in all cases.
    // Reading Asset files works just fine with the bare workflow on metro, but it doesn't work with the production build of APK/AAB.
    // Therefore, the code below does not work
    //var sb64 = await FileSystem.readAsStringAsync(require('../../assets/custom/base_image_for_wrapping.png'), {encoding: 'base64'});
    //var s = await EncodeFromB64ToBinary(await LoadBaseImageAssetFileB64());

    LogMe(0, 'WrapPicture(): Packaging metadata');
    const basedata = require('../../bundled_files/json/base_image_for_wrapping.png.json').data;

    // split
    LogMe(0, 'WrapPicture(): splitChunk: Started');
    var list = await ( async () => {
      switch ( PARAM_IMPLEMENTATION_OPTION_PNG ) {
        case 's': 
          LogMe(1, 'Packing PNG metadata: decoding from B64 to Binary string');
          const s = await EncodeFromB64ToBinary(basedata);
          LogMe(1, 'Packing PNG metadata: splitChunk');
          return await png.splitChunk(s);
        case 'b':
          LogMe(1, 'Packing PNG metadata: decoding from B64 to Buffer');
          const b = await EncodeFromB64ToBuffer(basedata);
          LogMe(1, 'Packing PNG metadata: splitChunk');
          return await png.splitChunkBufferTyped(b);
        default:
          throw new Error('Bug. Invalid PARAM_IMPLEMENTATION_OPTION_PNG: ' + PARAM_IMPLEMENTATION_OPTION_PNG);
      }
    } )();
    LogMe(0, 'WrapPicture(): splitChunk: Finished');
    
    // append
    LogMe(0, 'WrapPicture(): pop: Started');
    var iend = list.pop(); // remove IEND
    LogMe(0, 'WrapPicture(): pop: Finished');

    LogMe(0, 'WrapPicture(): ppPp createChunk: Started');
    /**
     * WARNING:
     * For png.createChunk(), you must use `new String('...')` for String literals!
     * Otherwise, png.crc32() str.charCodeAt() fails
     * I think it is because '' yields a string object, whereas "" yields a string object
     */
    //var newchunk1 = png.createChunkTyped(new String("ppPp"), ppPlainPictureObjectStr);
    // This is for ppPp
    var newchunk1 = ( () => {
      switch ( PARAM_IMPLEMENTATION_OPTION_PNG ) {
        case 's': 
          return png.createChunk("ppPp", ppPlainPictureObjectStr);
        case 'b':
          return png.createChunkTyped("ppPp", ppPlainPictureObjectStr);
        default:
          throw new Error('Bug. Invalid PARAM_IMPLEMENTATION_OPTION_PNG: ' + PARAM_IMPLEMENTATION_OPTION_PNG);
      }
    } )();
    LogMe(0, 'WrapPicture(): ppPp createChunk: Finished');

    // This is for ppPq
    LogMe(0, 'WrapPicture(): ppPq createChunk: Started');
    var newchunk2 = ( () => {
      switch ( PARAM_IMPLEMENTATION_OPTION_PNG ) {
        case 's': 
          return png.createChunk("ppPq", PP_PLATFORM_NICKNAME);
        case 'b':
          return png.createChunkTyped("ppPq", PP_PLATFORM_NICKNAME);
        default:
          throw new Error('Bug. Invalid PARAM_IMPLEMENTATION_OPTION_PNG: ' + PARAM_IMPLEMENTATION_OPTION_PNG);
      }
    } )();
    LogMe(0, 'WrapPicture(): ppPq createChunk: Finished');

    //See: https://en.wikipedia.org/wiki/PNG
    LogMe(0, 'WrapPicture(): Pushing chunks');
    list.push(newchunk1);  // Add our payload
    list.push(newchunk2);  // Tag with our PP platform nickname, for the recipient to know which PP platform to use to unwrap the picure

    // Not necessary:
    //var newchunk2 = png.createChunk("ppPt", "Wrapped private picture");
    //// See: https://en.wikipedia.org/wiki/PNG
    //list.push(newchunk2);

    list.push(iend);
    LogMe(0, 'WrapPicture(): Chunks pushed');

    LogMe(1, 'Printing list');
    for (i in list) {
      LogMe(1, 'size['+i+']: '+list[i].size);
      LogMe(1, 'type['+i+']: '+typeof list[i]);
    }

    // join
    LogMe(0, 'WrapPicture(): joinChunk: Started');
    var newpng = ( () => {
      switch ( PARAM_IMPLEMENTATION_OPTION_PNG ) {
        case 's': 
          return png.joinChunk(list);
        case 'b':
          return png.joinChunkBufferTyped(list);
        default:
          throw new Error('Bug. Invalid PARAM_IMPLEMENTATION_OPTION_PNG: ' + PARAM_IMPLEMENTATION_OPTION_PNG);
      }
    } )();
    LogMe(0, 'WrapPicture(): joinChunk: Finished');
    
    // save to file
    //fs.writeFileSync(outfile, newpng, 'binary');

    LogMe(1, 'WrapPicture(): newpng_B64 start B64 encoding, length in bytes='+newpng.length);
    // a Buffer.buffer gives an ArrayBuffer
    const newpng_retval = ( async () => {

      if (PARAM_IMPLEMENTATION_ARTIFACT_FORMAT==='utf8') {
        return newpng;
      }

      switch ( PARAM_IMPLEMENTATION_OPTION_B64 ) {
        case 'n': 
          return await EncodeFromBufferToB64(newpng);
        case 'q':
          return await EncodeFromArrayBufferToB64(newpng.buffer);
        case 's':
          return await EncodeFromBinaryToB64(newpng);
        default:
          throw new Error('Bug. Invalid PARAM_IMPLEMENTATION_OPTION_B64: ' + PARAM_IMPLEMENTATION_OPTION_B64);
      }
    } )();

    LogMe(1, 'WrapPicture(): newpng_B64 end B64 encoding');

    LogMe(0, 'WrapPicture(): Finished');

    return newpng_retval;
    
}
