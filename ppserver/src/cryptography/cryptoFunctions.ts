
//import Crypto from 'react-native-quick-crypto';
const Crypto = require('crypto');
const fs = require('fs')

import { EncodeFromB64ToBuffer, EncodeFromBufferToB64, LogMe } from '../serverLibrary';


// our cwd is the dist folder!
const PPserverPrivateKey = fs.readFileSync(require.resolve('../../../secrets/wrapping/rsa-privkey.pem')).toString();
console.log('Private key for wrapping, loaded');




export async function DecryptThings (requestDataObject: any) {
  LogMe(0, 'DecryptThings(): Started');
  LogMe(2, 'requestDataObject: ' + JSON.stringify(requestDataObject));

  // STAGE3
  LogMe(0, 'DecryptThings(): STAGE3');
  const stage2_key = Crypto.privateDecrypt(
    PPserverPrivateKey, 
    EncodeFromB64ToBuffer(requestDataObject.stage2.encrypted_stage2_key_b64)
  );

  //STAGE2
  LogMe(0, 'DecryptThings(): STAGE2');
  const cipher2 = Crypto.createDecipheriv(
    requestDataObject.stage2.encryption_algorithm, 
    stage2_key, 
    EncodeFromB64ToBuffer(requestDataObject.stage2.iv_b64)
  );
  LogMe(0, 'DecryptThings(): STAGE2: Writing');
  await cipher2.write(EncodeFromB64ToBuffer(requestDataObject.stage1.encrypted_stage1_key_and_params_b64));
  LogMe(0, 'DecryptThings(): STAGE2: Written');
  await cipher2.end();
  LogMe(0, 'DecryptThings(): STAGE2: Reading');
  const decrypted_stage1 = JSON.parse(await cipher2.read());
  LogMe(0, 'DecryptThings(): STAGE2: Read');

  // Here we get the privacy parameters
  const cipher2b = Crypto.createDecipheriv(
    requestDataObject.stage2.encryption_algorithm, 
    stage2_key, 
    EncodeFromB64ToBuffer(requestDataObject.stage2.iv_b64)
  );
  LogMe(0, 'DecryptThings(): STAGE2b: Writing');
  await cipher2b.write(EncodeFromB64ToBuffer(requestDataObject.stage1.ciphertext_to_server_data));
  LogMe(0, 'DecryptThings(): STAGE2b: Written');
  await cipher2b.end();
  LogMe(0, 'DecryptThings(): STAGE2b: Reading');
  const decrypted_to_server_data = JSON.parse(await cipher2b.read());
  LogMe(0, 'DecryptThings(): STAGE2b: Read');

  LogMe(1, 'decrypted_to_server_data='+JSON.stringify(decrypted_to_server_data));
  LogMe(0, 'DecryptThings(): Finished');
  return ({
    stage1: decrypted_stage1,
    to_server_data: decrypted_to_server_data,
  });

}




