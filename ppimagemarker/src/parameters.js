// Do not import custom libraries from here


// Console logging. 0=disabled, 1=normal logging, 2=verbose debugging
// NOTE: Setting this to anything other than 0 may significantly impact performance
// NOTE: Each log call (console.log()) is limited to 4096 bytes, so you won't see the full contents of image files
// See: https://stackoverflow.com/questions/8888654/android-set-max-length-of-logcat-messages
export const PARAM_LOGGING_LEVEL = 1;  // Change accordingly to your preference

/**
 * Name of the album where private pictures will be saved
 */
export const PARAM_PRIVATE_PICTURES_ALBUM_NAME = 'PrivatePics';

/**
 * Name of the directory where private pictures will be saved temporarily.
 * Note that this is not the directory where they will be saved permanently; 
 * the permanent directory is the one of the camera roll.
 */
export const PARAM_PRIVATE_PICTURES_TMP_DIRNAME = 'PrivatePicturesTmp';

export const PARAM_WELCOME_MESSAGE = 'Welcome to ppimagemarker. \
This apps lets you select the pictures you want to protect via the Privacy Provider framework, and assign privacy policies to them. \
It simply creates a copy of the selected pictures with EXIF metadata indicating that it is a private picture and what privacy \
policies it holds. This copy will be saved in a separate album called '+
PARAM_PRIVATE_PICTURES_ALBUM_NAME+
'\
. In Android, for pictures that are already in the PrivatePics album, they are updated directly. If you select a single picture from the PrivatePics album, we will preselect the current privacy policies that it has. \
If have recently built a new instance of the iOS app (e.g., from Xcode to IPA), we recommend to delete the PrivatePics album first, to avoid permission issues. Please allow full image gallery permissions.';

//https://exiftool.org/forum/index.php?topic=2960.0
//The first 8 bytes of the UserComment data specify the encoding.  For ASCII text, this is "ASCII\0\0\0".  For unknown encoding, use all zero bytes ("\0\0\0\0\0\0\0\0").
export const PARAM_EXIF_ASCII_PREFIX = "ASCII\u0000\u0000\u0000";