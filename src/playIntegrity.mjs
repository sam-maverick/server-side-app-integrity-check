
const jose = await import('jose');

const crypto = await import('crypto');

const { google } = await import('googleapis');

await import("dotenv/config");

const sharedlib = await import('./shared.js');





// get environment variables

function dieEnv(variable) {
  sharedlib.logEvent('ERROR', 'Environment variable not set: ' + variable, 1);
  process.exit(1);
}

const googleCredentials = process.env.GOOGLE_APPLICATION_CREDENTIALS;
const packageName = process.env.PACKAGE_NAME;
const encodedDecryptionKey = process.env.BASE64_OF_ENCODED_DECRYPTION_KEY;
const encodedVerificationKey = process.env.BASE64_OF_ENCODED_VERIFICATION_KEY;
const maxPartialDelayMsClassicOrIos = process.env.MAX_PARTIAL_DELAY_MS_CLASSIC_OR_IOS;
const maxPartialDelayMsStandard = process.env.MAX_PARTIAL_DELAY_MS_STANDARD;
const loggingLevel = process.env.LOGGING_LEVEL;
const appMinVersion = process.env.APP_MIN_VERSION;
const maxAllowedActivityLevel = process.env.MAX_ALLOWED_STANDARD_ACTIVITY_LEVEL

var certificates = process.env.VALID_CERTIFICATE_SHA256DIGEST;

if (!packageName) dieEnv("PACKAGE_NAME");
if (!googleCredentials) dieEnv("GOOGLE_APPLICATION_CREDENTIALS");
if (!encodedDecryptionKey) dieEnv("BASE64_OF_ENCODED_DECRYPTION_KEY");
if (!encodedVerificationKey) dieEnv("BASE64_OF_ENCODED_VERIFICATION_KEY");
if (!maxPartialDelayMsClassicOrIos) dieEnv("MAX_PARTIAL_DELAY_MS_CLASSIC_OR_IOS");
if (!maxPartialDelayMsStandard) dieEnv("MAX_PARTIAL_DELAY_MS_STANDARD");
if (!maxAllowedActivityLevel) dieEnv("MAX_ALLOWED_STANDARD_ACTIVITY_LEVEL");
if (!loggingLevel) dieEnv("LOGGING_LEVEL");
if (!certificates) dieEnv("VALID_CERTIFICATE_SHA256DIGEST");

const privatekey = JSON.parse(googleCredentials);

const playintegrity = google.playintegrity('v1');

var certificatesarray = JSON.parse(certificates);

if ( ! Array.isArray(certificatesarray) ) {
  sharedlib.logEvent('ERROR', 'Environment variable VALID_CERTIFICATE_SHA256DIGEST was expected to be an array.', 1);
  process.exit(1);
}
for (var i = 0; i < certificatesarray.length; i++) {  // Convert from HEX to BASE64URL format
  certificatesarray[i] = Buffer.from(certificatesarray[i].replaceAll(':',''), 'hex').toString('base64')
  .replaceAll('=','')
  .replaceAll('/','_')
  .replaceAll('+','-');
} 
const validCertificateSha256Digest = certificatesarray;
// We will use validCertificateSha256Digest in the code




////// FUNCTIONS



/**
 *
 * @param {string} token
 * @param {string} checkMode Must be either 'google' or 'server'. If the token came from a standard request, you must use 'google' or else the decryption will always fail; on-server decryption of standard requests is not supported by the official API.
 */

export async function decryptPlayIntegrity(token, checkMode) {
  if (checkMode === 'server') {
    sharedlib.logEvent('INFO', 'Processing token decryption and authentitation on-server. Google servers will not be contacted to perform this task.', 1);
    return await decryptPlayIntegrityServer(token);
  } else if (checkMode === 'google') {
    sharedlib.logEvent('INFO', 'Offloading token decryption and authentitation to Google servers.', 1);
    return await decryptPlayIntegrityGoogle(token);
  } else {
    return {status: "error", message: "Unknown checkMode "+checkMode};
  }
}

/**
 * decrypts the play integrity token on googles server with a google service account
 * @param {string} integrityToken
 * @returns
 */
async function decryptPlayIntegrityGoogle(integrityToken) {

  let jwtClient = new google.auth.JWT(
    privatekey.client_email,
    null,
    privatekey.private_key,
    ["https://www.googleapis.com/auth/playintegrity"]
  );

  google.options({ auth: jwtClient });

  const response = await playintegrity.v1.decodeIntegrityToken({
    packageName: packageName,
    requestBody: {
      integrityToken: integrityToken,
    },
  });
  sharedlib.logEvent('INFO', 'decryptPlayIntegrityGoogle: New client request processed', 1);
  sharedlib.logEvent('DEBUG', 'response.data.tokenPayloadExternal:'+JSON.stringify(response.data.tokenPayloadExternal), 2);

  return response.data.tokenPayloadExternal;
}

/**
 * decrypts the play integrity token locally on the server
 * @param {string} token
 * @returns
 */
async function decryptPlayIntegrityServer(token) {
  sharedlib.logEvent('DEBUG', 'encodedDecryptionKey:'+encodedDecryptionKey, 2);
  sharedlib.logEvent('DEBUG', 'token:'+token, 2);
  const decryptionKey = Buffer.from(encodedDecryptionKey, "base64");
  sharedlib.logEvent('DEBUG', 'decryptionKey length: '+decryptionKey.length, 2);
  const { plaintext, protectedHeader } = await jose.compactDecrypt(
    token,
    decryptionKey
  );
  let myverificationkey = crypto.createPublicKey(
    "-----BEGIN PUBLIC KEY-----\n" +
      encodedVerificationKey +
      "\n-----END PUBLIC KEY-----"
  );
  const { payload, Header = protectedHeader } = await jose.compactVerify(
    plaintext,
    myverificationkey
  );

  const payloadText = new TextDecoder().decode(payload);
  const payloadJson = JSON.parse(payloadText);
  sharedlib.logEvent('INFO', 'decryptPlayIntegrityServer: New client request processed', 1);
  sharedlib.logEvent('DEBUG', 'payloadJson:'+JSON.stringify(payloadJson), 2);
  return payloadJson;
}





/**
 * Checks the validity of a received token representing an attestation object
 * @param {string} decryptedToken Use the function decryptPlayIntegrity to decrypt the token
 * @param {string} none_truth Corresponds to the original nonce as generated by the server, or to the hash of the user action
 * @param {string} requestType Must be either 'classic' or 'standard'
 * @returns {object} {status: "success or fail or error", message: "Some explanatory message."}
 */
export async function verifyPlayIntegrity(decryptedToken, nonce_truth, requestType) {

  if (requestType !== 'classic' && requestType !== 'standard') {
    return {status: "error", message: "Invalid function call: requestType must be either 'classic' or 'standard'."};
  }

  // CHECK REQUEST DETAILS ////////////////////////////////////////////

  // check if requestDetails exists in decryptedToken
  var requestDetails = decryptedToken?.requestDetails;
  if (requestDetails == null) {
    return {status: "fail", message: "requestDetails not found in received token."};
  }

  // check if nonce is valid
  // - classic/standard cases are different
  var noncefield = undefined;  requestType === 'classic' ? noncefield = requestDetails?.nonce : noncefield = requestDetails?.requestHash ;
  var noncefieldname = undefined;  requestType === 'classic' ? noncefieldname = 'requestDetails.nonce' : noncefieldname = 'requestDetails.requestHash' ;
  // - check sanity
  if ( ! noncefield) {  // Field present?
    return {status: "fail", message: "Missing " + noncefieldname + " field in the token."};
  }
  if ( ! ((typeof noncefield) === 'string')) {  // Is of string type?
    return {status: "fail", message: "Wrong type for " + noncefieldname + ". We expected string. We found "+(typeof noncefield)+"."};
  }
  // - check value
  var nonce_received = noncefield;
  sharedlib.logEvent('DEBUG','nonce_truth:'+nonce_truth, 2);
  sharedlib.logEvent('DEBUG', 'nonce_received:'+nonce_received, 2);
  if (nonce_truth!==nonce_received) {
    return {status: "fail", message: "Nonce/Hash mismatch."};
  }

  // check request package name
  // - check sanity
  if ( ! requestDetails?.requestPackageName) {  // Field present?
    return {status: "fail", message: "Missing requestDetails.requestPackageName field in the token."};
  }
  if ( ! ((typeof requestDetails.requestPackageName) === 'string')) {  // Is of string type?
    return {status: "fail", message: "Wrong type for requestDetails.requestPackageName. We expected string. We found "+(typeof requestDetails.requestPackageName)+"."};
  }
  // - check value
  if (packageName !== requestDetails.requestPackageName) {
    return {status: "fail", message: "Invalid package name in the request."};
  }

  // check request isn't older than maxPartialDelayMs* seconds
  // - classic/standard cases are different
  var maxPartialDelayMs = undefined;  requestType === 'classic' ? maxPartialDelayMs = maxPartialDelayMsClassicOrIos : maxPartialDelayMs = maxPartialDelayMsStandard ;
  // - check sanity
  if ( ! requestDetails?.timestampMillis) {  // Field present?
    return {status: "fail", message: "Missing requestDetails.timestampMillis field in the token."};
  }
  if ( ! ((typeof requestDetails.timestampMillis) === 'string')) {  // Is of string type?
    return {status: "fail", message: "Wrong type for requestDetails.timestampMillis. We expected string. We found "+(typeof requestDetails.timestampMillis)+"."};
  }
  if ( ! sharedlib.isInteger(requestDetails.timestampMillis)) {  // Can be cast to non-negative integer?
    return {status: "fail", message: "Wrong contents for requestDetails.timestampMillis. We expected to find only decimal digits."};
  }
  // - check value
  if (Date.now() - requestDetails.timestampMillis > maxPartialDelayMs) {
    return {status: "fail", message: "Request too old. Took to long from generating the token on the user device API to checking it on our server."};
  }

  sharedlib.logEvent('INFO', 'Attested device has valid requestDetails', 1);


  // CHECK DEVICE INTEGRITY ////////////////////////////////////////////

  // check if deviceIntegrity exists in decryptedToken
  var deviceIntegrity = decryptedToken?.deviceIntegrity;
  if (deviceIntegrity == null) {
    return {status: "fail", message: "deviceIntegrity not found in received token"};
  }

  // check if deviceRecognitionVerdict meets maximum standards. If the device is rooted, it should give UNEVALUATED.
  // - check sanity
  if ( ! deviceIntegrity?.deviceRecognitionVerdict) {  // Field present?
    return {status: "fail", message: "Missing deviceIntegrity.deviceRecognitionVerdict field in the token."};
  }
  if ( ! ((typeof deviceIntegrity.deviceRecognitionVerdict) === 'object')) {  // Is of object type?
    return {status: "fail", message: "Wrong type for deviceIntegrity.deviceRecognitionVerdict. We expected object. We found "+(typeof deviceIntegrity.deviceRecognitionVerdict)+"."};
  }
  if ( ! Array.isArray(deviceIntegrity.deviceRecognitionVerdict)) {  // Is it an array?
    return {status: "fail", message: "We expected deviceIntegrity.deviceRecognitionVerdict to be an array."};
  }
  // - check value
  if (deviceIntegrity.deviceRecognitionVerdict.includes("MEETS_VIRTUAL_INTEGRITY")){
    return {status: "fail", message: "Only meets virtual integrity (MEETS_VIRTUAL_INTEGRITY). Likely running on emulator."};
  } else if ( ! deviceIntegrity.deviceRecognitionVerdict.includes("MEETS_DEVICE_INTEGRITY")){
    return {status: "fail", message: "Device does not meet MEETS_DEVICE_INTEGRITY."};
  } else if ( ! deviceIntegrity.deviceRecognitionVerdict.includes("MEETS_BASIC_INTEGRITY")){
    return {status: "fail", message: "Device does not meet MEETS_BASIC_INTEGRITY."};
  } else if ( ! deviceIntegrity.deviceRecognitionVerdict.includes("MEETS_STRONG_INTEGRITY")){
    return {status: "fail", message: "Device does not meet MEETS_STRONG_INTEGRITY."};
  } else {
    sharedlib.logEvent('INFO', 'Attested device has valid deviceRecognitionVerdict', 1);
    sharedlib.logEvent('DEBUG', 'deviceIntegrity.deviceRecognitionVerdict: '+deviceIntegrity.deviceRecognitionVerdict, 2);
  }

  // CHECK RECENT DEVICE ACTIVITY ////////////////////////////////////////////
  // This field is within the deviceIntegrity field !!

  // NOTE: As of 11-June-2024, this feature is no longer in beta and is available for both Classic and Standard requests
  // https://developer.android.com/google/play/integrity/setup#optional_device_information

  // check if recentDeviceActivity exists in decryptedToken
  var recentDeviceActivity = decryptedToken?.deviceIntegrity?.recentDeviceActivity;
  if (recentDeviceActivity == null) {
    return {status: "fail", message: "deviceIntegrity.recentDeviceActivity not found in received token."};
  }

  // check if deviceActivityLevel meets maximum standards.
  if ( ! recentDeviceActivity?.deviceActivityLevel) {  // Field present?
    return {status: "fail", message: "Missing deviceIntegrity.recentDeviceActivity.deviceActivityLevel field in the token."};
  }
  if ( ! ((typeof recentDeviceActivity.deviceActivityLevel) === 'string')) {  // Is of string type?
    return {status: "fail", message: "Wrong type for deviceIntegrity.recentDeviceActivity.deviceActivityLevel. We expected string. We found "+(typeof recentDeviceActivity.deviceActivityLevel)+"."};
  }
  // - check value
  if (recentDeviceActivity.deviceActivityLevel == "UNEVALUATED"){
    return {status: "fail", message: "deviceIntegrity.recentDeviceActivity.deviceActivityLevel is UNEVALUATED."};
  }
  var attestedDeviceActivityLevel = undefined;
  switch(recentDeviceActivity.deviceActivityLevel) {
    case 'LEVEL_1':
      attestedDeviceActivityLevel = 1;
      break;
    case 'LEVEL_2':
      attestedDeviceActivityLevel = 2;
      break;
    case 'LEVEL_3':
      attestedDeviceActivityLevel = 3;
      break;
    case 'LEVEL_4':
      attestedDeviceActivityLevel = 4;
      break;
    default:
      return {status: "fail", message: "deviceIntegrity.recentDeviceActivity.deviceActivityLevel had an unexpected value. Values must be within LEVEL_1, LEVEL_2, LEVEL_3, and LEVEL_4."};     
  }
  if (attestedDeviceActivityLevel > maxAllowedActivityLevel) {
    return {status: "fail", message: "deviceIntegrity.recentDeviceActivity.deviceActivityLevel showed a value beyond our allowed limits. The maximum that is allowed is LEVEL_"+maxAllowedActivityLevel+". We found LEVEL_"+attestedDeviceActivityLevel+"."};     
  }

  sharedlib.logEvent('INFO', 'Attested device has valid deviceActivityLevel', 1);
  sharedlib.logEvent('DEBUG', 'recentDeviceActivity.deviceActivityLevel: '+recentDeviceActivity.deviceActivityLevel, 2);


  // CHECK APP INTEGRITY ////////////////////////////////////////////

  // check if appIntegrity exists in decryptedToken
  var appIntegrity = decryptedToken?.appIntegrity;
  if (appIntegrity == null) {
    return {status: "fail", message: "appIntegrity not found in received token."};
  }
  
  // check if appRecognitionVerdict is anything other than PLAY_RECOGNIZED (e.g. UNEVALUATED)
  // - check sanity
  if ( ! appIntegrity?.appRecognitionVerdict) {  // Field present?
    return {status: "fail", message: "Missing appIntegrity.appRecognitionVerdict field in the token."};
  }
  if ( ! ((typeof appIntegrity.appRecognitionVerdict) === 'string')) {  // Is of string type?
    return {status: "fail", message: "Wrong type for appIntegrity.appRecognitionVerdict. We expected string. We found "+(typeof appIntegrity.appRecognitionVerdict)+"."};
  }
  // - check value
  if (appIntegrity.appRecognitionVerdict != "PLAY_RECOGNIZED") {
    return {status: "fail", message: "appRecognitionVerdict is "+appIntegrity.appRecognitionVerdict+"."};
  }

  // check package name
  // - check sanity
  if ( ! appIntegrity?.packageName) {  // Field present?
    return {status: "fail", message: "Missing appIntegrity.packageName field in the token."};
  }
  if ( ! ((typeof appIntegrity.packageName) === 'string')) {  // Is of string type?
    return {status: "fail", message: "Wrong type for appIntegrity.packageName. We expected string. We found "+(typeof appIntegrity.packageName)+"."};
  }
  // - check value
  if (packageName != appIntegrity.packageName) {
    return {status: "fail", message: "Invalid package name in the token."};
  }

  // check app versionCode
  // - check sanity
  if ( ! appIntegrity?.versionCode) {  // Field present?
    return {status: "fail", message: "Missing appIntegrity.versionCode field in the token."};
  }
  if ( ! ((typeof appIntegrity.versionCode) === 'string')) {  // Is of string type?
    return {status: "fail", message: "Wrong type for appIntegrity.versionCode. We expected string. We found "+(typeof appIntegrity.versionCode)+"."};
  }
  if ( ! sharedlib.isInteger(appIntegrity.versionCode)) {  // Can be cast to non-negative integer?
    return {status: "fail", message: "Wrong contents for appIntegrity.versionCode. We expected to find only decimal digits."};
  }
  // - check value
  if (parseInt(appMinVersion,10) > parseInt(appIntegrity.versionCode,10)) {
    return {status: "fail", message: "Invalid version code of the app. The app is running an outdated version. The app version is "+appIntegrity.versionCode+". Minimum version is "+appMinVersion+"."};
  }

  // check certificateSha256Digest
  // - check sanity
  if ( ! appIntegrity?.certificateSha256Digest) {  // Field present?
    return {status: "fail", message: "Missing appIntegrity.certificateSha256Digest field in the token."};
  }
  if ( ! ((typeof appIntegrity.certificateSha256Digest) === 'object')) {  // Is of object type?
    return {status: "fail", message: "Wrong type for appIntegrity.certificateSha256Digest. We expected object. We found "+(typeof appIntegrity.certificateSha256Digest)+"."};
  }
  if ( ! Array.isArray(appIntegrity.certificateSha256Digest)) {  // Is it an array?
    return {status: "fail", message: "We expected appIntegrity.certificateSha256Digest to be an array."};
  }
  if( appIntegrity.certificateSha256Digest.length != 1) {  // Does the array have exactly one element?
    return {status: "fail", message: "We expected appIntegrity.certificateSha256Digest to be an array with exactly one element. Found"+appIntegrity.certificateSha256Digest.length+"."};
  }

  // - check value
  if ( ! validCertificateSha256Digest.includes(appIntegrity.certificateSha256Digest[0])) {
    return {status: "fail", message: "Invalid certificateSha256Digest."};
  }

  sharedlib.logEvent('INFO', 'Attested device has valid appIntegrity', 1);
  

  // CHECK PLAY PROTECT ////////////////////////////////////////////

  // check if deviceIntegrity exists in decryptedToken
  var environmentDetails = decryptedToken?.environmentDetails;
  if (environmentDetails == null) {
    return {status: "fail", message: "environmentDetails not found in received token."};
  }

  // check if playProtectVerdict meets maximum standards. If the device is rooted, it should give UNEVALUATED.
  // - check sanity
  if ( ! environmentDetails?.playProtectVerdict) {  // Field present?
    return {status: "fail", message: "Missing environmentDetails.playProtectVerdict field in the token."};
  }
  if ( ! ((typeof environmentDetails.playProtectVerdict) === 'string')) {  // Is of object type?
    return {status: "fail", message: "Wrong type for environmentDetails.playProtectVerdict. We expected string. We found "+(typeof environmentDetails.playProtectVerdict)+"."};
  }
  // - check value
  if (environmentDetails.playProtectVerdict !== "NO_ISSUES"){
    sharedlib.logEvent('DEBUG', 'environmentDetails.playProtectVerdict: '+environmentDetails.playProtectVerdict, 2);
    return {status: "fail", message: "Play Protect status failed. Expected NO_ISSUES. Found " + environmentDetails.playProtectVerdict + "."};
  } 

  sharedlib.logEvent('INFO', 'Attested device has valid environmentDetails', 1);

  
  // CHECK ACCOUNT INTEGRITY ////////////////////////////////////////////

  // check if accountDetails exists in decryptedToken
  var accountIntegrity = decryptedToken?.accountDetails;
  if (accountIntegrity == null) {
    return {status: "fail", message: "accountIntegrity not found in received token."};
  }

  // check if appLicensingVerdict is LICENSED.
  // - check sanity
  if ( ! accountIntegrity?.appLicensingVerdict) {  // Field present?
    return {status: "fail", message: "Missing accountIntegrity.appLicensingVerdict field in the token."};
  }
  if ( ! ((typeof accountIntegrity.appLicensingVerdict) === 'string')) {  // Is of string type?
    return {status: "fail", message: "Wrong type for accountIntegrity.appLicensingVerdict. We expected string. We found "+(typeof accountIntegrity.appLicensingVerdict)+"."};
  }
  // - check value
  if (accountIntegrity.appLicensingVerdict !== "LICENSED") {
    return {status: "fail", message: "appLicensingVerdict is "+accountIntegrity.appLicensingVerdict+"."};
  }
  
  sharedlib.logEvent('INFO', 'Attested device has valid accountIntegrity', 1);

  return {status: "success", message: "Successful"};
  
}
