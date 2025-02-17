import FileProvider from 'react-native-file-provider';
import 'react-native-url-polyfill/auto';  // https://www.davidangulo.xyz/posts/use-url-class-in-react-native/
import * as Linking from 'expo-linking';
import AppLink from 'react-native-app-link';
import { Mutex, Semaphore, withTimeout, tryAcquire, E_ALREADY_LOCKED, E_TIMEOUT } from 'async-mutex';
import * as params from './update-parameters';
import * as UpdUtils from './update-utils';
var SendIntentAndroid = require('react-native-send-intent');
import * as piexif from 'piexifjs';
import * as RNQB64 from 'react-native-quick-base64';

import { Platform } from 'react-native';
import { v4 as uuidv4 } from 'uuid';

import * as FileSystem from 'expo-file-system';

import * as ImagePicker from 'expo-image-picker';
import { LogMe } from '../src/myGeneralLibrary';




const LIBN = '(emclient) (PrivatePictureAPI)';
var mutexPrivatePictureAccess = withTimeout(new Mutex(), params.PARAM_PP__SELECT_TIMEOUT_MS);
var PPreplyAuthenticationString = '';
var PPselectorResult = new Error('Unitinitalized - internal error');  // null means successful, otherwise it contains the error object
var PPandroidContentUri = '';
var PPTmpFilePath = '';
var PPiosFileContents = '';

const png = require('png-metadata');
const Buffer = require('buffer').Buffer;
var mutexPrivatePictureDisplay = withTimeout(new Mutex(), params.PARAM_PP__DISPLAY_TIMEOUT_MS);




Linking.addEventListener('url', async ({ url }) => {
  UpdUtils.LogSys(LIBN, 1, 'URL event triggered for: ' + url);

  try {

    PPselectorResult = null;  // Initially, we assume no error

    const URLofEvent = new URL(url);  // https://developer.mozilla.org/en-US/docs/Web/API/URL

    if (URLofEvent.hostname === params.PARAM_PP__APP_URL_MESSAGING_DISPLAY_HOSTNAME) {
      if (URLofEvent.searchParams.get('authToken') === PPreplyAuthenticationString) {
        // Authentication successful
        if (URLofEvent.searchParams.get('result') === 'report') {
          let ReportingNotImplementedMessage = 'You requested to report the following picture:\n'+
          URLofEvent.searchParams.get('RefImageUri')+'\n'+
          '\n'+
          'However, this function is not yet implemented.';
          await UpdUtils.AsyncAlert(ReportingNotImplementedMessage);
          PPselectorResult = new Error(ReportingNotImplementedMessage);
        } else if (URLofEvent.searchParams.get('result') !== 'success') {
          PPselectorResult = new Error('There has been an error unwrapping the private picture: '+URLofEvent.searchParams.get('message'));
        } else {
          // Success
          // This will go to the finally clause and then return
        }
      } else {
        PPselectorResult = new Error('Authentication failed. The callback from the PP client did not contain the valid authentication token.');
      }  
    } else if (URLofEvent.hostname === params.PARAM_PP__APP_URL_MESSAGING_SELECTOR_HOSTNAME) {
      UpdUtils.LogSys(LIBN, 0, 'Control is returned to messaging app');
      if (URLofEvent.searchParams.get('authToken') === PPreplyAuthenticationString) {
        // Authentication successful
        if (URLofEvent.searchParams.get('result') !== 'success') {
          PPselectorResult = new Error('There has been an error wrapping the private picture: '+URLofEvent.searchParams.get('message'));
        } else {
          if (Platform.OS === 'ios') {
            PPiosFileContents = URLofEvent.searchParams.get('fileContents');  // https://www.typescriptlang.org/docs/handbook/release-notes/typescript-2-0.html#non-null-assertion-operator
            if (PPiosFileContents === null) {
              PPselectorResult = new Error('Missing fileContents in iOS device.');
            }
          }
        
          // This will go to the finally clause and then return

        }
      } else {
        PPselectorResult = new Error('Authentication failed. The callback from the PP client did not contain the valid authentication token.');
      }
    } else {
      //PPselectorResult = new Error('We received an invalid host value for an incoming deep link request: '+URLofEvent.host);
      UpdUtils.LogSys(LIBN, 1, 'This deeplink request does not correspond to us: '+URLofEvent.hostname);
      return;
    }

  } catch(err) {
    PPselectorResult = err;
  } finally {
    mutexPrivatePictureAccess.release();  // This will allow to continue processing in (*)
    UpdUtils.LogSys(LIBN, 1, 'mutexPrivatePictureAccess released by callback'); 
  }
});


async function CreateTmpDirIfNotExists() {
  UpdUtils.LogSys(LIBN, 0, 'Creating dir '+params.PARAM_PP__APP_TMP_FOLDER_NAME+' if not exists');
  // Create dir for exchanging files with PP client, if it does not exist
  try {
      await FileSystem.makeDirectoryAsync(params.PARAM_PP__APP_TMP_BASE_DIR + params.PARAM_PP__APP_TMP_FOLDER_NAME);
  }
  // Ignored -- Directory already exists
  // We can't distinguish between 'directory already exists' and other types of errors
  catch(err) { 
    // Do nothing
    UpdUtils.LogSys(LIBN, 1, 'Ignoring error');
    UpdUtils.LogSys(LIBN, 2, err?.stack);
  }
  UpdUtils.LogSys(LIBN, 0, 'Dir operation finished');
}


/**
 * Pick a picture from the phone gallery. If the picture is private, it gets automatically wrapped.
 * See: https://docs.expo.dev/versions/latest/sdk/imagepicker/
 * @param PickPictureOptions A map of launchImageLibraryAsync options, conforming to the ImagePicker API.
 * @return A Promise that resolves to an object, conforming to the ImagePicker API. If an error occurs it is raised.
 */
export async function PickPicture(PickPictureOptions) {

  if (PickPictureOptions?.allowsMultipleSelection) {
      throw Error('allowsMultipleSelection not yet supported within PrivatePictureAPI');
  }

  let result = await ImagePicker.launchImageLibraryAsync(PickPictureOptions);

  if ((result.canceled) || ( ! result?.assets)) {
     return result;
  }

  LogMe(1, "result.assets[0]: "+JSON.stringify(result.assets[0]));

  let fileUri;
  const fileUriWithExtension = result.assets[0].uri;;
  const fileOptions = {encoding: 'base64'};

  if (Platform.OS === 'android') {
    fileUri = result.assets[0].uri;
  } else if (Platform.OS === 'ios') {
    fileUri = 'ph://' + result.assets[0].assetId;
    // If we pick the uri property, we can read the file but iOS silently drops the metadata. This is probably
    // because the API that gives access to files via manual selection is more restrictive that the APIs that
    // allow apps with full gallery permissions to read files. On the flip side, only the uri property has the 
    // extension
  }

  LogMe(1, "fileUri: "+fileUri);
  
  // Uncomment this block only if necessary, as it incurs in 0.01 ms overhead  
  //let fileinfo = await FileSystem.getInfoAsync(fileUri, {size: true});
  //UpdUtils.LogSys(LIBN, 0, 'Original File size, in bytes: ' + fileinfo.size);

  // Checking if picture is marked as 'Private picture' or not
  let isPrivatePicture = false;
  let fileContentsOriginalB64 = '';
  let fileContentsOriginalBinary = '';
  let metadata = {
    pictureType: '',
    privacyPolicies: {
      ViewOnce: '',
      Expiration: '',
      KeepOpenTimer: '',
    }
  }; // Just for Type consistency
  
  let fileExt;

  try {
  
    fileExt = fileUriWithExtension?.split('.')?.pop()?.toLowerCase();
    LogMe(1, "fileExt: "+fileExt);
    if (fileExt=='jpg') { fileExt='jpeg' }  // piexif.insert() library replaces jpg by jpeg
    if ( ! UpdUtils.IsValidImageExtensionAndContentType(fileExt)) {              
      throw Error('Image URI extension is not valid: '+fileExt);  
    }
    if (fileExt!='jpeg' &&  fileExt!='tiff') {
      // Unsupported              
      throw Error('Image extension '+fileExt+' is not supported. Only jpg/jpeg and tiff images are supported.');  
    }
    // Get exif data as object. jpegData must be a string that starts with "data:image/jpeg;base64,"(DataURL), "\xff\xd8", or "Exif".
    UpdUtils.LogSys(LIBN, 0, 'Reading file');
    
    var dataUri = '';

    if (Platform.OS === 'android') {

      fileContentsOriginalB64 = await FileSystem.readAsStringAsync(fileUri, {encoding: 'base64'});

    } else if (Platform.OS === 'ios') {

      // iOS does not allow to read image files directly from the camera roll unless they are 
      // selected explicitly and individually with a native API (expo-image-multiple-picker uses 
      // loose permissions to massively access the image gallery)
      // Therefore, we work with a temporal copy
      let uriInCacheLoadPolicies = FileSystem.cacheDirectory + "/" + uuidv4() + "." + fileExt;
      await FileSystem.copyAsync({
          from: fileUri,
          to: uriInCacheLoadPolicies,
      });

      fileContentsOriginalB64 = await FileSystem.readAsStringAsync(uriInCacheLoadPolicies, {encoding: 'base64'});

      await FileSystem.deleteAsync(uriInCacheLoadPolicies, {idempotent: true});    
    }
  
    UpdUtils.LogSys(LIBN, 0, 'readAsStringAsync() called');

    dataUri = 'data:image/'+fileExt+';base64,'+fileContentsOriginalB64;
    /**
     *     switch (params.PARAM_IMPLEMENTATION_FILE_READWRITE) {
     *       case 'b':
     *         UpdUtils.LogSys(LIBN, 1, 'b');
     *         fileContentsOriginalB64 = await FileSystem.readAsStringAsync(fileUri, {encoding: 'base64'});
     * 
     *         switch (params.PARAM_IMPLEMENTATION_ATOB_DEDUPLICATION) {
     *           case 'y':
     *             UpdUtils.LogSys(LIBN, 1, 'y');
     *             fileContentsOriginalBinary = RNQB64.atob(fileContentsOriginalB64); //from base64 to binary string
     *             break;
     *           case 'n':
     *             UpdUtils.LogSys(LIBN, 1, 'n');
     *             dataUri = 'data:image/'+fileExt+';base64,'+fileContentsOriginalB64;
     *             break;
     *           default:
     *             throw new Error('Bug. Unrecognized option for params.PARAM_IMPLEMENTATION_ATOB_DEDUPLICATION: '+params.PARAM_IMPLEMENTATION_ATOB_DEDUPLICATION);
     *         }
     *     
     *         break;
     *       case 'a':
     *         UpdUtils.LogSys(LIBN, 1, 'a');
     *         fileContentsOriginalBinary = await UpdUtils.ReadFileAsArrayBuffer(fileUri);
     *         break;
     *       default:
     *         throw new Error('Bug. Unrecognized option for params.PARAM_IMPLEMENTATION_FILE_READWRITE: '+params.PARAM_IMPLEMENTATION_FILE_READWRITE);
     *     }
     * 
     */

    UpdUtils.LogSys(LIBN, 0, 'File loaded');
    UpdUtils.LogSys(LIBN, 0, 'Checking if picture is marked as private');

    const retval = piexif.isPrivatePicture(fileContentsOriginalBinary=='' ? dataUri : fileContentsOriginalBinary);
    isPrivatePicture = retval.isPrivatePicture;
    metadata = retval.metadata;
    UpdUtils.LogSys(LIBN, 1, 'FastDetect; metadata = '+JSON.stringify(metadata));
    /**
     *     switch (params.PARAM_IMPLEMENTATION_EXIF_PRIVATE_PICTURE_DETECTOR) {
     *       case 'd':
     *         UpdUtils.LogSys(LIBN, 1, 'd');
     *         const retval = piexif.isPrivatePicture(fileContentsOriginalBinary=='' ? dataUri : fileContentsOriginalBinary);
     *         isPrivatePicture = retval.isPrivatePicture;
     *         metadata = retval.metadata;
     *         UpdUtils.LogSys(LIBN, 1, 'FastDetect; metadata = '+JSON.stringify(metadata));
     *         break;
     *       case 'l':
     *         UpdUtils.LogSys(LIBN, 1, 'l');
     *         var exifObj = piexif.load(fileContentsOriginalBinary=='' ? dataUri : fileContentsOriginalBinary);
     *         //UpdUtils.LogSys(LIBN, 2,'exifObj: '+JSON.stringify(exifObj));
     *     
     *         if (exifObj?.Exif) {
     *           UpdUtils.LogSys(LIBN, 1,'ExifIFD.UserComment exists in metadata: '+exifObj['Exif'][piexif.ExifIFD.UserComment]);
     *           try {
     *             metadata = JSON.parse(exifObj['Exif'][piexif.ExifIFD.UserComment]);
     *             if (metadata?.pictureType === 'private') {
     *               UpdUtils.LogSys(LIBN, 1,'The picture is private!');
     *               isPrivatePicture = true;
     *             }  
     *           } catch (exc) {
     *             UpdUtils.LogSys(LIBN, 1, 'Error parsing JPEG metadata. Possible another program is using the same field for other purposes. This error will be ignored. Message: '+exc.message);
     *           }
     *         }
     *         break;
     *       default:
     *         throw new Error('Bug. Unrecognized option for params.PARAM_IMPLEMENTATION_EXIF_PRIVATE_PICTURE_DETECTOR: ' + params.PARAM_IMPLEMENTATION_EXIF_PRIVATE_PICTURE_DETECTOR);
     *     }
     */
    UpdUtils.LogSys(LIBN, 0, 'Check done');
    
  } catch(exc) {
    UpdUtils.LogSys(LIBN, 1, exc.message);
  }


  if (isPrivatePicture) {  // package it calling ppclient's deep link
    UpdUtils.LogSys(LIBN, 0, 'Processing a private picture *.*.*.*.');
    try {
      return await tryAcquire(mutexPrivatePictureAccess).runExclusive(async() => {  // tryAcquire => non-blocking; if mutex is busy it throws error

        UpdUtils.LogSys(LIBN, 1, 'mutexPrivatePictureAccess acquired to begin operations');

        // Prepare and launch deep link

        // NOTE: Deep link params are only available in the EAS build
        let URLofPPselectionService = new URL(params.PARAM_PP__SERVICE_WRAP_BASE_URL);
        URLofPPselectionService.searchParams.append('callbackURL', params.PARAM_PP__APP_URL_SCHEME+'://'+params.PARAM_PP__APP_URL_MESSAGING_SELECTOR_HOSTNAME+'/');
        PPreplyAuthenticationString = UpdUtils.GenerateRandomString(params.PARAM_PP__LENGTH_AUTH);
        URLofPPselectionService.searchParams.append('authToken', PPreplyAuthenticationString);
        URLofPPselectionService.searchParams.append('privacyPolicies', UpdUtils.SafeUrlEncodeForB64(UpdUtils.EncodeFromBinaryToB64(JSON.stringify(metadata.privacyPolicies))));
        URLofPPselectionService.searchParams.append('operationName', 'wrap');
        // We assume that the extension coincides with the ISO content-type            
        if ( ! UpdUtils.IsValidImageExtensionAndContentType(fileExt)) {
            throw Error('Image URI extension is not valid.');                   
        }            

        await CreateTmpDirIfNotExists();

        // This will be our cache file
        PPTmpFilePath = params.PARAM_PP__APP_TMP_BASE_DIR + params.PARAM_PP__APP_TMP_FOLDER_NAME + '/' + uuidv4() + '.tmp.' + fileExt;

        //await Linking.openURL(URLofPPselectionService.toString());  // Need to await Linking.openURL() to properly catch errors
        if (Platform.OS === 'android') {

          // ANDROID ---------------------------------------------------------------------------
          
          UpdUtils.LogSys(LIBN, 1, 'Preparing temporary image file; this is the file with plain contents');
          // Prepare temporary image file with plain contents
          //UTF8 encoded strings cannot represent arbitrary binary values
          //https://docs.snowflake.com/en/sql-reference/binary-input-output
          UpdUtils.LogSys(LIBN, 2, 'fileContentsOriginalB64: '+fileContentsOriginalB64);
          UpdUtils.LogSys(LIBN, 1, 'fileContentsOriginalB64 length: '+fileContentsOriginalB64.length);

          UpdUtils.LogSys(LIBN, 0, 'Writing tmp file');

          await FileSystem.copyAsync({from: fileUri, to: PPTmpFilePath});
          /**
           *           switch ( params.PARAM_IMPLEMENTATION_FILE_COPY ) {
           *             case 'b': 
           *               await FileSystem.writeAsStringAsync(PPTmpFilePath, fileContentsOriginalB64, {encoding: 'base64'});
           *               break;
           *             case 'c':
           *               await FileSystem.copyAsync({from: fileUri, to: PPTmpFilePath});
           *               break;
           *             default:
           *               throw new Error('Bug. Invalid params.PARAM_IMPLEMENTATION_FILE_COPY: ' + params.PARAM_IMPLEMENTATION_FILE_COPY);
           *           }
           */

          UpdUtils.LogSys(LIBN, 0, 'Tmp file written');
          UpdUtils.LogSys(LIBN, 1, 'Full path is: '+PPTmpFilePath);
  
          PPandroidContentUri = await FileProvider.getUriForFile(params.PARAM_PP__APP_ANDROID_FILEPROVIDER_AUTHORITY, PPTmpFilePath)
          UpdUtils.LogSys(LIBN, 1, 'FileProvider contentUri: ' + PPandroidContentUri);
          // Note that persistent Content-URI permissions require to make the user manually selects a document via the Storage Access Framework (ActivityResultContracts.OpenMultipleDocuments())
          // https://stackoverflow.com/questions/54826883/is-there-a-way-to-keep-permanent-access-to-resources-exposed-with-fileprovider-a
          await FileProvider.grantUriPermissionRW(params.PARAM_PP__PPCLIENT_ANDROID_NAME, PPandroidContentUri);
          UpdUtils.LogSys(LIBN, 1, 'FileProvider RW permission granted');
          URLofPPselectionService.searchParams.append('fileUri', PPandroidContentUri);

        } else if (Platform.OS === 'ios') {

          // iOS ---------------------------------------------------------------------------

          UpdUtils.LogSys(LIBN, 0, 'Preparing URL');

          URLofPPselectionService.searchParams.append('fileUri', fileUriWithExtension);
          URLofPPselectionService.searchParams.append('fileContents', UpdUtils.SafeUrlEncodeForB64(
            await
            ( async () => {
              return fileContentsOriginalB64;
              /**
               *               switch ( params.PARAM_IMPLEMENTATION_FILE_READWRITE ) {
               *                 case 'b': 
               *                   return fileContentsOriginalB64;
               *                 case 'a':
               *                   return await UpdUtils.EncodeFromArrayBufferToB64(fileContentsOriginalB64);
               *                 default:
               *                   throw new Error('Bug. Invalid params.PARAM_IMPLEMENTATION_FILE_READWRITE: ' + params.PARAM_IMPLEMENTATION_FILE_READWRITE);
               *               }
               */
            } )()
          ));
          UpdUtils.LogSys(LIBN, 0, 'URL prepared');

        } else {

          throw new Error('Unsupported platform: '+Platform.OS);

        }
        
        /**
         *         // In Android, the AppLink.maybeOpenURL() command below is equivalent to:
         *         let wasOpened = await SendIntentAndroid.openAppWithData(
         *           'pt.lasige.safex.ppclient',
         *           URLofPPselectionService.toString(),
         *           //PPandroidContentUri,
         *           null,
         *           null
         *         );
         */
    
        UpdUtils.LogSys(LIBN, 0, 'URL call to open is about to be triggered');

        await AppLink.maybeOpenURL(
          URLofPPselectionService.toString(), 
          { 
            appName : params.PARAM_PP__SERVICE_APPNAME,
            appStoreId : params.PARAM_PP__SERVICE_IOSAPPID,
            appStoreLocale : params.PARAM_PP__SERVICE_IOSAPPSTORELOCALE,
            playStoreId : params.PARAM_PP__SERVICE_PLAYSTOREID,
          },
          async function(){ await UpdUtils.AsyncAlert('You will be prompted to install the PP client app. Once installed, come back here and select your picture again.'); }
        );  // We need to pass a callback function to show the Alert, because Alerts are not shown when the app is in the background.
            // See: https://stackoverflow.com/questions/74662876/popup-alert-dialog-in-react-native-android-app-while-app-is-not-in-foreground
            
        UpdUtils.LogSys(LIBN, 0, 'URL call to open has completed');
        UpdUtils.LogSys(LIBN, 2, 'URL is: ' + URLofPPselectionService.toString());

        // (*) Blocks execution; awaits processing of PP app
        await mutexPrivatePictureAccess.acquire();
        UpdUtils.LogSys(LIBN, 0, 'Execution is resumed');

        if (PPselectorResult == null) {
          // Do stuff
          UpdUtils.LogSys(LIBN, 1, 'Returning to PrivatePictureAPI on a private picture'); 

          let retcontents = {};
          retcontents.assets = [{}];
          retcontents.assets[0].uri = PPTmpFilePath;

          if (Platform.OS === 'android') {
            // Nothing to do.
          } else {  // ios
            let iosfilecontents;
            UpdUtils.LogSys(LIBN, 0, 'Decoding file from URL');
            if (fileOptions.encoding == 'base64') {
                iosfilecontents = await UpdUtils.SafeUrlDecodeForB64(PPiosFileContents);
            } else {
                iosfilecontents = await UpdUtils.SafeUrlDecodeForB64(UpdUtils.EncodeFromB64ToUTF8(PPiosFileContents));
            } 
            UpdUtils.LogSys(LIBN, 0, 'File URL-decoded');
            UpdUtils.LogSys(LIBN, 0, 'Writing to file');
            await FileSystem.writeAsStringAsync(PPTmpFilePath, iosfilecontents, fileOptions);
            UpdUtils.LogSys(LIBN, 0, 'File written');
          }
          UpdUtils.LogSys(LIBN, 0, 'Returning');
          return retcontents;
        } else {
          throw PPselectorResult;
        }

      });
    } catch (e) {
      if (e === E_ALREADY_LOCKED) {
        UpdUtils.LogSys(LIBN, 1, 'There is another operation in progress'); 
        // We need to throw alert here to make the calling app aware that the read operation has not completed
        throw new Error('There is another operation in progress. Wait until the operation completes and try again.');
      } else if (e === E_TIMEOUT) {
        UpdUtils.LogSys(LIBN, 1, 'mutexPrivatePictureAccess released by timeout'); 
        throw new Error('There has been a timeout. Make sure that the PP client app is installed. Keep the PP client app in the foreground while it is processing information.');
      } else {
        UpdUtils.LogSys(LIBN, 1, 'An error has occurred: '+e.stack); 
        throw e;
      }
    } finally {
      UpdUtils.LogSys(LIBN, 0, 'Finally clause');
      /**
       * NOTE: if we do
       *   const mutexRelease = await mutexPrivatePictureAccess.acquire();
       * then,
       *   mutexRelease() is equivalent to mutexPrivatePictureAccess.release().
       * 
       * NOTE: mutexRelease() is idempotent.
       */

      //mutexPrivatePictureAccess.release();  // NOT necessary to release here!!

      try {
        if (Platform.OS === 'android') {
          if (PPandroidContentUri!=='') {
            await FileProvider.revokeUriPermissionRW(PPandroidContentUri); 
            UpdUtils.LogSys(LIBN, 1, 'PPandroidContentUri permissions revoked on '+PPandroidContentUri); 
          } else {
            UpdUtils.LogSys(LIBN, 1, 'PPandroidContentUri permissions NOT revoked on PPandroidContentUri because it is empty');  // In case there was previously an exception
          }
          // We do NOT delete the file because it is referenced in our return value. The calling app needs to access the file!
          /**
           *           if (PPTmpFilePath!=='') {
           *             await FileSystem.deleteAsync(PPTmpFilePath, {idempotent: true});  // With {idempotent: true}, it does not throw error if the file does not exist.
           *             UpdUtils.LogSys(LIBN, 1, 'Temporary file deleted: '+PPTmpFilePath); 
           *           } else {
           *             UpdUtils.LogSys(LIBN, 1, 'Temporary file of PPTmpFilePath NOT deleted because path is empty'); 
           *           }
           */
        }
      } catch (err) {
        UpdUtils.LogSys(LIBN, 1, 'Error when revoking permissions (cleanup): '+err.stack); 
      }     
      UpdUtils.LogSys(LIBN, 0, 'End of: Finally clause');
    }
  } else {  // It is not a private picture
    UpdUtils.LogSys(LIBN, 0, 'Processing a NON-private picture *.*.*.*.');
    let retvalnonprivate = {};
    retvalnonprivate.assets = [{}];
    retvalnonprivate.assets[0].uri = fileUriWithExtension;
    UpdUtils.LogSys(LIBN, 0, 'Returning');
    return retvalnonprivate;
  }

}










/**
 * Show a picture from an image file located in the app storage. If the picture is private, it gets automatically unwrapped.
 * @param imageUri Uri of the local file corresponding to the picture.
 * @return true if it is a private picture (in which case the API shows the picture for you and you do 
 * not have to do any further processing); false otherwise (in which case you are in charge of displaying 
 * the picture as you would regularly do). If an error occurs, it is raised.
 */
export async function ShowPicture(imageUri) {

    UpdUtils.LogSys(LIBN, 0, 'ShowPicture() called for: '+imageUri);

    // Checking if picture is a wrapped private picture or not
    let isWrappedPrivatePicture = false;
    let PPplatformNickname = false;
    let contentsInsideEnvelope = false;
    let fileContentsOriginal;

    // Uncomment this block only if necessary, as it incurs in 0.1 ms overhead
    //let fileinfo = await FileSystem.getInfoAsync(imageUri, {size: true});
    //UpdUtils.LogSys(LIBN, 0, 'Wrapped File size, in bytes: ' + fileinfo.size);

    try {

        UpdUtils.LogSys(LIBN, 0, 'Reading file');
        fileContentsOriginal = await FileSystem.readAsStringAsync(imageUri, {encoding: 'base64'});
        UpdUtils.LogSys(LIBN, 0, 'File loaded');
        UpdUtils.LogSys(LIBN, 0, 'Checking file type');

        // If it is in JPEG format, then it is definitely not a private picture

        if (fileContentsOriginal.length<4)  { throw new Error('Tiny file; it can\'t hold a picture'); }
        const magicjpegB64 = fileContentsOriginal.substring(0, 4);
        if (magicjpegB64 === '/9j/')  { throw new Error('It is a JPEG file; therefore it can\'t be a wrapped private picture'); }

        // Assuming it is in PNG, we check here that it has the chunk metadata expected for a wrapped private picture        
        
        let s = UpdUtils.EncodeFromB64ToBinary(fileContentsOriginal);

        UpdUtils.LogSys(LIBN, 1, 'Parsing PNG metadata');
        let list = png.splitChunk(s);
        UpdUtils.LogSys(LIBN, 2, 'Metadata contents:'+JSON.stringify(list));

        if (list !== false) {
          list.forEach(function (arrayItem) {
            if (arrayItem?.type === 'ppPp' && arrayItem?.data) {
                UpdUtils.LogSys(LIBN, 1, 'Found ppPp chunk');
                contentsInsideEnvelope = JSON.parse(arrayItem.data);  // This holds the payload
            }
            if (arrayItem?.type === 'ppPq' && arrayItem?.data) {
                UpdUtils.LogSys(LIBN, 1, 'Found ppPq chunk');
                isWrappedPrivatePicture = true;
                PPplatformNickname = arrayItem.data;  // This holds the PP platform nickname
            }
          });
        }

    } catch(exc) {
        UpdUtils.LogSys(LIBN, 1, 'Catched exception while checking if picture is a wrapped private picture or not: ' + exc.message);
    }

    UpdUtils.LogSys(LIBN, 0, 'Check done');
    if (isWrappedPrivatePicture) {  // check if the file is a wrapped private picture, and if so unwrap it calling its deep link
        UpdUtils.LogSys(LIBN, 0, 'We have a wrapped private picture *.*.*.*.');
        try {
            await tryAcquire(mutexPrivatePictureDisplay).runExclusive(async() => {  // tryAcquire => non-blocking; if mutex is busy it throws error
                UpdUtils.LogSys(LIBN, 0, 'mutexPrivatePictureDisplay acquired to begin operations');
        
                if (PPplatformNickname===false) {
                    throw Error('Found a ppPq chunk without a ppPp chunk.');
                }

                if ( ! params.PARAM_PP__PLATFORM_NICKNAME_UNWRAPPING_LIST.includes(PPplatformNickname)) {
                    throw Error('The ppPq chunk indicates a PP platform nickname that is not in our allowed list.');
                }

                // Prepare and launch deep link
        
                // NOTE: Deep link params are only available in the EAS build
                let URLofPPselectionService = new URL(
                    params.PARAM_PP__SERVICE_WRAPUNWRAP_BASE_URL_PART1+
                    PPplatformNickname+
                    params.PARAM_PP__SERVICE_WRAPUNWRAP_BASE_URL_PART2
                );
                URLofPPselectionService.searchParams.append('callbackURL', params.PARAM_PP__APP_URL_SCHEME+'://'+params.PARAM_PP__APP_URL_MESSAGING_DISPLAY_HOSTNAME+'/');
                PPreplyAuthenticationString = UpdUtils.GenerateRandomString(params.PARAM_PP__LENGTH_AUTH);
                URLofPPselectionService.searchParams.append('authToken', PPreplyAuthenticationString);
                URLofPPselectionService.searchParams.append('operationName', 'unwrap');
                URLofPPselectionService.searchParams.append('imageUriReference', imageUri);
                
                // We assume that the extension coincides with the ISO content-type            
                let fileExt = imageUri.split('.').pop();
                if (!UpdUtils.IsValidImageExtensionAndContentType(fileExt)) {
                    throw Error('Image URI extension is not valid.');                   
                }       

                await CreateTmpDirIfNotExists();

                //await Linking.openURL(URLofPPselectionService.toString());  // Need to await Linking.openURL() to properly catch errors
                if (Platform.OS === 'android') {
        
                    // ANDROID ---------------------------------------------------------------------------
          
                    UpdUtils.LogSys(LIBN, 2, 'fileContentsOriginal: '+fileContentsOriginal);
                    UpdUtils.LogSys(LIBN, 1, 'fileContentsOriginal length: '+fileContentsOriginal.length);
                    UpdUtils.LogSys(LIBN, 1, 'Preparing temporary image file; this is the file with wrapped contents');
                    // Prepare temporary image file with wrapped contents
                    //UTF8 encoded strings cannot represent arbitrary binary values
                    //https://docs.snowflake.com/en/sql-reference/binary-input-output
                    PPTmpFilePath = params.PARAM_PP__APP_TMP_BASE_DIR + params.PARAM_PP__APP_TMP_FOLDER_NAME + '/' + uuidv4() + '.tmp.' + fileExt;
                    UpdUtils.LogSys(LIBN, 1, 'PPTmpFilePath='+PPTmpFilePath);
                    /**
                     * We need to copy the wrapped image file onto a temporary file in a specific directory. 
                     * This is because we have set permissions over what directories can contain files that 
                     * are shared via the FileProvider API (otherwise, a 'Failed to find configured root that 
                     * contains' error is raised). In our case, only the params.PARAM_PP__APP_TMP_FOLDER_NAME is set 
                     * to have this permission, as set in the android-manifest-fileprovider-definitions.js 
                     * plugin. In this messagning app, image files are located in the chatHistoryPictures 
                     * folder. Once the ppclient has finished displaying the private picture, the Finally 
                     * clause below will be in charge of deleting the temporary file.
                     */
                    UpdUtils.LogSys(LIBN, 0, 'Writing file');
                    await FileSystem.writeAsStringAsync(PPTmpFilePath, fileContentsOriginal, {encoding: 'base64'});
                    UpdUtils.LogSys(LIBN, 0, 'File written');
                    UpdUtils.LogSys(LIBN, 1, 'Full path is: '+PPTmpFilePath);

                    PPandroidContentUri = await FileProvider.getUriForFile(params.PARAM_PP__APP_ANDROID_FILEPROVIDER_AUTHORITY, PPTmpFilePath);
                    UpdUtils.LogSys(LIBN, 0, 'FileProvider contentUri: ' + PPandroidContentUri);
                    await FileProvider.grantUriPermissionR(params.PARAM_PP__PPCLIENT_ANDROID_NAME, PPandroidContentUri);
                    UpdUtils.LogSys(LIBN, 0, 'FileProvider R permission granted');
                    URLofPPselectionService.searchParams.append('fileUri', PPandroidContentUri);
            
                } else if (Platform.OS === 'ios') {
        
                    // iOS ---------------------------------------------------------------------------
        
                    UpdUtils.LogSys(LIBN, 0, 'Preparing URL');
                    URLofPPselectionService.searchParams.append('fileContents', UpdUtils.SafeUrlEncodeForB64(fileContentsOriginal));
                    UpdUtils.LogSys(LIBN, 0, 'URL prepared');
        
                } else {
        
                    throw new Error('Unsupported platform: '+Platform.OS);
        
                }
                
                //// In Android, the AppLink.maybeOpenURL() command below is equivalent to:
                //let wasOpened = await SendIntentAndroid.openAppWithData(
                //'pt.lasige.safex.ppclient',
                //URLofPPselectionService.toString(),
                ////PPandroidContentUri,
                //null,
                //null
                //);
                    
                UpdUtils.LogSys(LIBN, 0, 'About to call URL to open');

                await AppLink.maybeOpenURL(
                    URLofPPselectionService.toString(), 
                    { 
                        appName : params.PARAM_PP__SERVICE_APPNAME,
                        appStoreId : params.PARAM_PP__SERVICE_IOSAPPID,
                        appStoreLocale : params.PARAM_PP__SERVICE_IOSAPPSTORELOCALE,
                        playStoreId : params.PARAM_PP__SERVICE_PLAYSTOREID,
                    },
                    async function(){ await UpdUtils.AsyncAlert('You will be prompted to install the PP client app. Once installed, come back here and tap on the picture again.'); }
                );  // We need to pass a callback function to show the Alert, because Alerts are not shown when the app is in the background.
                    // See: https://stackoverflow.com/questions/74662876/popup-alert-dialog-in-react-native-android-app-while-app-is-not-in-foreground
                    
                UpdUtils.LogSys(LIBN, 0, 'URL call to open has completed');
                UpdUtils.LogSys(LIBN, 2, 'URL is: ' + URLofPPselectionService.toString());
        
                
                // (*) Blocks execution; awaits processing of PP app
                await mutexPrivatePictureDisplay.acquire();
                UpdUtils.LogSys(LIBN, 0, 'Execution resumed');
        
        
                if (PPselectorResult != null) {
                    throw PPselectorResult;
                } else {
                    // No error - continue
                }
        
            });
        } catch (e) {
            if (e === E_ALREADY_LOCKED) {
                UpdUtils.LogSys(LIBN, 1, 'There is another operation in progress'); 
                // Instead of throwing an error, we show a warning message. We deem a 'picture visualisation operation' to be safely idempotent
                await UpdUtils.AsyncAlert('There is another private picture viualisation in progress. Tap the back button on the PP client app or wait for the timeout, and try again.');
            } else if (e === E_TIMEOUT) {
                UpdUtils.LogSys(LIBN, 1, 'mutexPrivatePictureDisplay released by timeout'); 
                throw new Error('There has been a timeout. Make sure that the PP client app is installed. Keep the PP client app in the foreground while it is processing information.');
            } else {
                UpdUtils.LogSys(LIBN, 1, 'An error has occurred: '+e.stack); 
                throw e;
            }
        } finally {
            UpdUtils.LogSys(LIBN, 0, 'Finally clause');
            // NOTE: if we do
            //  const mutexRelease = await mutexPrivatePictureAccess.acquire();
            // then,
            //  mutexRelease() is equivalent to mutexPrivatePictureAccess.release().
            //
            // NOTE: mutexRelease() is idempotent.
            //
        
            //mutexPrivatePictureAccess.release();  // NOT necessary to release here!!
        
            try {
                if (Platform.OS === 'android') {
                    if (PPandroidContentUri != '') {
                        await FileProvider.revokeUriPermissionR(PPandroidContentUri); 
                        UpdUtils.LogSys(LIBN, 1, 'PPandroidContentUri permissions revoked on '+PPandroidContentUri); 
                    } else {
                        UpdUtils.LogSys(LIBN, 1, 'PPandroidContentUri permissions NOT revoked on PPandroidContentUri because it is empty');  // In case there was previously an exception
                    }
                    if (PPTmpFilePath != '') {
                        await FileSystem.deleteAsync(PPTmpFilePath, {idempotent: true});  // With {idempotent: true}, it does not throw error if the file does not exist.
                        UpdUtils.LogSys(LIBN, 1, 'Temporary file deleted: '+PPTmpFilePath); 
                    } else {
                        UpdUtils.LogSys(LIBN, 1, 'Temporary file of PPTmpFilePath NOT deleted because path is empty'); 
                    }
                } else {
                    // iOS: No cleanup
                }
            } catch (err) {
                UpdUtils.LogSys(LIBN, 1, 'Error when cleaning up after picture display: '+err.stack); 
            } finally {
                UpdUtils.LogSys(LIBN, 0, 'End of: Finally clause');
                UpdUtils.LogSys(LIBN, 0, 'Returning from ShowPicture() on a private picture'); 
                return true;
            }
    
        }
    } else {  // It is not a private picture
        // continue
        UpdUtils.LogSys(LIBN, 0, 'Resuming from ShowPicture() on a picture that is not a wrapped private picture *.*.*.*.'); 
        return false
    }

}