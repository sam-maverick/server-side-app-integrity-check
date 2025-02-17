// Parameters of the Updated OS layer

import * as FileSystem from 'expo-file-system';

/**
 * Console logging.
 * -1=disabled, 0=performance metrics, 1=normal logging, 2=verbose debugging
 * NOTE: Setting this to anything other than 0 may significantly impact performance
 * NOTE: Each log call (console.log()) is limited to 4096 bytes, so you won't see the full contents of image files
 * https://stackoverflow.com/questions/8888654/android-set-max-length-of-logcat-messages
 */

export const PARAM_LOGGING_LEVEL = 0;  // Change accordingly to your preference

/**
 * Timeout after which a the private picture selection will give error if no aswer is received from the pp client app.
 * This parameter is for the cases where a user selects a picture and the app requests
 * to put an envelope to send it to another user, and the ppclient does not respond because
 * the user manually cancelled the process by killing the ppclient, or otherwise.
 */
export const PARAM_PP__SELECT_TIMEOUT_MS = 60*1000;

/**
 * Timeout after which a the private picture display request will give error if the pp client app does not call back.
 * This parameter is for the cases where a user taps onto a received picture and the app requests
 * to display it, and the ppclient does not call back (with a deep link or intent) to the messaging app because
 * the user manually cancelled the process by killing the ppclient, or otherwise.
 * This makes sure that Lightbox.js processing is blocked until *after* the call to AppLink.maybeOpenURL() is issued
 */
export const PARAM_PP__DISPLAY_TIMEOUT_MS = 1*1000;

/**
 * The nickname idetifying the PP platform that will be used to wrap pictures.
 * This must correspond with the PP_PLATFORM_NICKNAME of your ppclient of choice.
 */
export const PARAM_PP__PLATFORM_NICKNAME_WRAPPING = "gen";

/**
 * The nicknames of accepted PP platforms for unwrapping pictures.
 */
export const PARAM_PP__PLATFORM_NICKNAME_UNWRAPPING_LIST = [
    "gen",
    "droid",
    "ios",
];

/** 
 * URL parts for wrapping and unwrapping pictures. 
 */
export const PARAM_PP__SERVICE_WRAPUNWRAP_BASE_URL_PART1 = 'pripro-';
export const PARAM_PP__SERVICE_WRAPUNWRAP_BASE_URL_PART2 = '://wrapoperation/';  // With trailing /

/** 
 * URL for accessing the ppclient's screen for unwrapping a private picture. You should not need to touch this.
 */
export const PARAM_PP__SERVICE_WRAP_BASE_URL = PARAM_PP__SERVICE_WRAPUNWRAP_BASE_URL_PART1 + PARAM_PP__PLATFORM_NICKNAME_WRAPPING + PARAM_PP__SERVICE_WRAPUNWRAP_BASE_URL_PART2;

/** 
 * PP app name
 */
export const PARAM_PP__SERVICE_APPNAME = 'ppclient';

/** 
 * PP app ID on the App Store (iOS), in string format
 */
export const PARAM_PP__SERVICE_IOSAPPID = '6502830043';

/** 
 * App Store's locale (iOS) where to find the PP app
 */
export const PARAM_PP__SERVICE_IOSAPPSTORELOCALE = 'us';

/** 
 * PP app package identifier on the Play Store (Android)
 */
export const PARAM_PP__SERVICE_PLAYSTOREID = 'pt.lasige.safex.ppclient';

/**
 * Protocol/Scheme of this app, to handle deep links
 * This must be consistent with the configuration in app.json
 */
export const PARAM_PP__APP_URL_SCHEME = 'enhmsm';

/**
 * Hostname part of the link that the ppclient will call after processing a picture selection request.
 */
export const PARAM_PP__APP_URL_MESSAGING_SELECTOR_HOSTNAME = 'backfromPPselector';

/**
 * Hostname part of the link that the ppclient will call after processing a picture display request.
 */
export const PARAM_PP__APP_URL_MESSAGING_DISPLAY_HOSTNAME = 'backfromPPdisplay';

/**
 * Charset and length of the authentication string that the app will send to the ppclient to verify the response.
 * Characters must be URL safe
 */
export const PARAM_PP__CHARSET_AUTH = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
export const PARAM_PP__LENGTH_AUTH = 16;

/**
 * Folder name (last leaf) where temporary image files are stored for exchange with other apps, within the messaging app.
 */
export const PARAM_PP__APP_TMP_FOLDER_NAME = 'ppSharedImages';

/**
 * Base directory (starting root) where temporary image files are stored for exchange with other apps, within the messaging app.
 *
 * CAUTION:
 * If you want to migrate this to another place (e.g., cacheDirectory), you must set the appropriate permissions 
 * to that folder for the Android FileProvider.
 * In a real world implementation of the architecture, this folder is not within the user space but within the OS,
 * and the file can be automatically deleted when they are no more references to it. If supported, it can also be a
 * virtual file in memory.
 */
export const PARAM_PP__APP_TMP_BASE_DIR = FileSystem.documentDirectory;


/**
 * Android name given to the messaging app
 */
export const PARAM_PP__APP_ANDROID_FILEPROVIDER_AUTHORITY = 'pt.lasige.safex.enhmessageme.MyFileProvider';

/**
 * Android name given to the PP client app
 */
export const PARAM_PP__PPCLIENT_ANDROID_NAME = 'pt.lasige.safex.ppclient';

/**
 * How JPEG private pictures are detected
 * 'l' for piexifjs.load.
 * 'd' for custom function, more efficient.
 */
//export const PARAM_IMPLEMENTATION_EXIF_PRIVATE_PICTURE_DETECTOR = 'l';

/**
 * How files are loaded
 * 'b' for base-64 string, with 'expo-file-system' module.
 * 'a' for ArrayBuffer, with the FileReader Android native module; however:
 *    reader.readAsArrayBuffer() only accepts Blob or File
 *    File objects are collected when the user manually selects a file, so it is out of our scope here
 *    See: https://developer.mozilla.org/en-US/docs/Web/API/FileReader/readAsDataURL
 * Experimental - do not use.
 */
//export const PARAM_IMPLEMENTATION_FILE_READWRITE = 'b';

/**
 * How files are copied
 * 'b' for base-64 string, with 'expo-file-system' module writeAsStringAsync().
 * 'c' for copyAsync(), with 'expo-file-system' module.
 */
//export const PARAM_IMPLEMENTATION_FILE_COPY = 'c';

/**
 * 'n' for none.
 * 'y' for deduplication technique.
 */
//export const PARAM_IMPLEMENTATION_ATOB_DEDUPLICATION = 'n';

/**
 * 'n' for normal processing.
 * 'y' When piexif.js is called, it checks if it is a PNG picture by reading the first bytes, 
 * and if so, it determines it is a non-private picture because private pictures are JPEG by definition.
 */
export const PARAM_IMPLEMENTATION_PNG_FASTCHECK_NONPRIVATE = 'y';

//https://exiftool.org/forum/index.php?topic=2960.0
//The first 8 bytes of the UserComment data specify the encoding.  For ASCII text, this is "ASCII\0\0\0".  For unknown encoding, use all zero bytes ("\0\0\0\0\0\0\0\0").
export const PARAM_EXIF_ASCII_PREFIX = "ASCII\u0000\u0000\u0000";