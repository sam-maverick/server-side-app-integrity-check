
//     DANGER ZONE !!!!!!!

/**
 * When set to true, the server will accept all attestations/assertions requests as valid
 */
export const PARAM_TEST_MODE = false;

/**
 * Set to true for https; false for http
 */
export const PARAM_HTTPS_ENABLED = true;

//     END OF DANGER ZONE



/**
 * A nickname idetifying your PP platform. This is the PP platform that you own.
 * Maximum 5 characters!!!!
 * 
 * NOTE: THIS PARAMETER IS NOT NECESSARY HERE
 * 
 */
//export const PP_PLATFORM_NICKNAME = "gen";


export const PARAM_API_PORT = 3020;


export const PARAM_DATABASE_URL = "mongodb://127.0.0.1:27017/ppmessagemedb";

/**
 * Console logging.
 * -1= disabled, 0=performance metrics, 1=normal logging, 2=verbose debugging
 * NOTE: Setting this to anything other than 0 may significantly impact performance
 * IMPORTANT NOTE: Setting this to 2 bridges error messages directly from libraries (such as the spic-library-custom),
 * which can potentially contain sensitive data.
 */
export const PARAM_LOGGING_LEVEL = 0;    // Change accordingly to your preference

/**
 * According to https://developer.android.com/google/play/integrity/classic
 * these are the requirements for the nonce in Android:
    String
    URL-safe
    Encoded as Base64 and non-wrapping
    Minimum of 16 characters
    Maximum of 500 characters

 * According to https://developer.android.com/google/play/integrity/standard
 * these are the requirements for the requestHash in Android:
    The value set in the requestHash field has a maximum length of 500 bytes.
    Caution: Never put any sensitive information as plain-text into the requestHash argument. Instead, hash all the input by default.
 */
export const PARAM_CHARSET_TOKENS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
export const PARAM_LENGTH_TOKENS = 200;

/** 
 * Minimum Android version that client devices must have. This is to reject devices that run old OS versions with known vulnerabilities.
 * Note that this corresponds to the API level, rather than the Android version.
 * According to https://developer.android.com/google/play/integrity/classic#compare-standard
 * Standard requests are supported in Android 5.0 (API level 21) or higher.
 * Classic requests are supported in Android 4.4 (API level 19) or higher.
*/
export const MINIMUM_ANDROID_API_LEVEL = 28;

/**
 * This parameter only affects Android's classic API requests
 * 'server' --> check token locally on server (no network connection is used to perform the task)
 * 'google' --> offload check to google servers (Google servers are contacted via internet)
 */
export const ANDROID_CHECK_MODE = 'server';

/**
 * See https://developer.apple.com/account > Apps > <your_app>
 */
export const IOS_BUNDLE_ID = 'pt.lasige.safex.ppclient';

/**
 * See https://developer.apple.com/account#MembershipDetailsCard
 */
export const IOS_TEAM_ID = 'L549K3FQ5X';  // Does not change when creating new app if published under the same developer account&team

/** 
 * Minimum iOS version that client devices must have. This is to reject devices that run old OS versions with known vulnerabilities.
 * You do not necessarily have to accept only maintained versions. You may include non-maintained versions that do not have 
 * vulnerabilities that affect the App Attest API.
 * Note that 
 * Because multiple versions might be supported, we use semantic versioning
 * https://semver.org/
 * https://github.com/isaacs/node-semver
 * According to https://developer.apple.com/news/?id=2sngpulc
 * App Attest API requires iOS 14 or later, so setting any version prior to 14 as a supported version does not make sense.
*/
export const IOS_SUPPORTED_VERSIONS = '>=14.8.1 || >=15.8.1 || >=16.7.5 || >=17.3.1 || >=18.x';

/**
 * This parameter only affects iOS.
 * https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server
 * This parameter is used to tell the server what is the environment for iOS attestations (Development or
 * or Production). Apple keeps a separate database for each environment; so the server does the same.
 * 
 * This must match the environment in which the phone operates. If the app is deployed via Xcode, then it is a 
 * Development environment; Production otherwise.
 * 
 * ToDo: We could send this parameter to the client and then the client could check if there is a mismatch. 
 * If this parameter does not match the environment of the phone, the ppclient will get a 
 * "fail_aaguid_mismatch" error during enrollment when trying to attest its generated key.
 * 
 * NOTE:
 * https://developer.apple.com/documentation/devicecheck/preparing-to-use-the-app-attest-service
 * "If instead you want to use the App Attest production servers during development, add the App Attest Environment  
 * [https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_developer_devicecheck_appattest-environment] 
 * entitlement to your app’s entitlements file, and set the associated value to production. Regardless of how you 
 * set the entitlement, your app always operates in production mode after distribution, whether through TestFlight, 
 * the App Store, or the Apple Developer Enterprise Program."
 *  
 * Deploying as Debug or as Release (see eas.json in ppclient), does not seem to impact this parameter.
 */
export const IOS_IS_DEVELOPMENT_ENVIRONMENT = false;

/**
 * Maximum time between token generation, and token validation
 */
export const MAX_TOTAL_DELAY_MS = {
   'android_classic': 90000,
   'android_standard': 90000,
   'ios_attestation': 90000,
   'ios_assertion': 90000,
};
