// Do not import custom libraries from here

// NOTE: When changes are made to files that do not contain components, these changes are not pulled to running apps in real time. You need to re-launch the app to force a re-download.

import * as Device from 'expo-device';


// Quality of the image (resampling)
// from 0 to 1, float. 0=lowest resolution, 1=highest resolution
// NOTE: In some devices, only 1 is supported!!!! Check:
// https://github.com/expo/expo/issues/19512
// https://github.com/react-native-image-picker/react-native-image-picker/blob/a5d2938cd19e1d26614bd78c89d3e02467da28a6/docs/Reference.md#options
export const PARAM_IMAGE_PICKER_QUALITY = 1;

let server_host = '';
if (Device.isDevice) {
    server_host = '192.168.12.1';  // Change accordingly to your network environment.
} else {
    server_host = '10.0.2.2';  // Do not change. 10.0.2.2 is used as loopback address of the emulator host by Expo Go.
}

export const PARAM_SERVER_API_URL = 'http://' + server_host + ':3010'; // Change port if needed

export const PARAM_SERVER_WS_URL = 'ws://' + server_host + ':3011'; // Change port if needed

export const PARAM_IMAGES_DIRNAME = 'chatHistoryPictures';  // You shouldn't need to change this

// Console logging
// -1=disabled, 0=performance metrics, 1=normal, 2=verbose
// NOTE: Setting this to anything other than 0 may significantly impact performance
// NOTE: Each log call (console.log()) is limited to 4096 bytes, so you won't see the full contents of image files
// Check: https://stackoverflow.com/questions/8888654/android-set-max-length-of-logcat-messages
export const PARAM_LOGGING_LEVEL = 0;  // Change accordingly to your preference

