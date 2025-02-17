//import { StatusBar } from 'expo-status-bar';
import React, {useState, useCallback, useEffect, useRef, useMemo} from 'react';
import { StyleSheet, Button, Text, TextInput, View, Alert, ScrollView, Platform, Image } from 'react-native';

import * as FileSystem from 'expo-file-system';
import uuid from 'react-native-uuid';

import RadioGroup from 'react-native-radio-buttons-group';

import { ImagePicker, Album, Asset } from 'expo-image-multiple-picker';
import * as ExpoImagePicker from 'expo-image-picker';
import * as MediaLibrary from 'expo-media-library';

import * as piexif from 'piexifjs';
import { CameraRoll } from "@react-native-camera-roll/camera-roll";

import { TabsComponent } from './Tabs.jsx';

import { styles } from './myVisualsLibrary.jsx';
import { 
    EraseLocalData, 
    ErrorAlert, 
    LogMe, 
    WriteMyFileStream,
    UpdateLogMeUsername, 
    IsValidImageExtensionAndContentType,
    AsyncAlert,
 } from '../myGeneralLibrary.jsx';

 import { 
    PARAM_PRIVATE_PICTURES_ALBUM_NAME,
    PARAM_PRIVATE_PICTURES_TMP_DIRNAME,
    PARAM_WELCOME_MESSAGE,
    PARAM_EXIF_ASCII_PREFIX,
 } from '../parameters.js';

import storage from '../storage/storageApi.js';

//import * as AndroidPermanentMediaOverwritePermissions from 'android-permanent-media-overwrite-permissions';

// NOTE: iOS does not provide albumId for selected picture file assets; therefore in iOS we do not detect when picture is from PrivatePics album

export const PPTaggingComponent = (props) => {

    const [initStatus, setInitStatus] = useState({ key: 'init' });
    const [privateAlbumID, setPrivateAlbumId] = useState({ key: 0 });
    const [lastSelectedAlbumID, setLastSelectedPrivateAlbumId] = useState({ key: 0 });
    const [imagePermissionsGranted, setImagePermissionsGranted] = useState(false);
    const [isProcessing, setIsProcessing] = useState(false);
    const [processingMessage, setProcessingMessage] = useState();
    const [propsState, setPropsState] = useState(props.route.params);

    LogMe(1, 'Initial propsState.AccountData: '+JSON.stringify(propsState.AccountData));

    // Image picker
    const [open, setOpen] = useState(true);
    //const [album, setAlbum] = useState<Album | undefined>();
    const [album, setAlbum] = useState();
    //const [assets, setAssets] = useState<Asset[]>([]);
    const [assets, setAssets] = useState();

    const [statusUsePermissions, usePermissions] = MediaLibrary.usePermissions();

    // Privacy policies
    const [selectionViewOnce, setSelectionViewOnce] = useState();
    const [selectionExpiration, setSelectionExpiration] = useState();
    const [selectionKeepOpenTimer, setSelectionKeepOpenTimer] = useState();
    const [selectionInfoMessage, setSelectionInfoMessage] = useState();

    async function ExecuteTheMarking () {
        LogMe(1,'ExecuteTheMarking() called'); 

        setProcessingMessage('Processing image(s). Please wait.');
        setIsProcessing(true);

        try {
    
            // LIMITATION: We can't delete files in shared storage, with the regular permissions
            // In Android, to delete files in shared storage we need to use special APIs

            for (let i = 0; i < assets.length; i++) {

                let hopefullyReadableUri;
                let uriWithExtension;
                if (Platform.OS === 'android') {
                    hopefullyReadableUri = assets[i].uri;
                    uriWithExtension = assets[i].uri;
                } else if (Platform.OS === 'ios') {
                    hopefullyReadableUri = assets[i].uri;
                    uriWithExtension = (await MediaLibrary.getAssetInfoAsync(assets[i])).localUri;
                } else {
                    ErrorAlert('Platform not supported: '+Platform.OS);  
                    return; 
                }

                LogMe(2, "assets[i]: "+JSON.stringify(assets[i]));
                LogMe(2, "hopefullyReadableUri: "+hopefullyReadableUri);
                LogMe(2, "uriWithExtension: "+uriWithExtension);

                let fileExt = uriWithExtension.split('.').pop().toLowerCase();
                if (fileExt=='jpg') { fileExt='jpeg' }  // piexif.insert() library replaces jpg by jpeg
                if (!IsValidImageExtensionAndContentType(fileExt)) {
                    ErrorAlert('Image URI extension is not valid: '+fileExt);  
                    return;                 
                } 
                if (fileExt!='jpeg' &&  fileExt!='tiff') {
                    // Unsupported
                    ErrorAlert('Image extension '+fileExt+' is not supported. Only jpg/jpeg and tiff images are supported.');
                    return;
                }
                // Get exif data as object. jpegData must be a string that starts with "data:image/jpeg;base64,"(DataURL), "\xff\xd8", or "Exif".
                LogMe(1,'ExecuteTheMarking(): readAsStringAsync');

                let uriInCache = FileSystem.cacheDirectory + "/" + uuid.v4() + "." + fileExt;
                await FileSystem.copyAsync({
                    from: hopefullyReadableUri,
                    to: uriInCache,
                });
                LogMe(1, "Selected file " + hopefullyReadableUri + " was copied to "+uriInCache);

                LogMe(1, "readAsStringAsync() : ");

                let fileContentsOriginal = await FileSystem.readAsStringAsync(uriInCache, {encoding: 'base64'});
                let dataUri = 'data:image/'+fileExt+';base64,'+fileContentsOriginal;
                //LogMe(2,'ExecuteTheMarking(): dataUri: ----'+dataUri);
                LogMe(1,'ExecuteTheMarking(): piexif.load');
                let exifObj = piexif.load(dataUri);
                LogMe(2,'exifObj original: '+JSON.stringify(exifObj));
    
                let newValue = PARAM_EXIF_ASCII_PREFIX + JSON.stringify({
                    pictureType: 'private',
                    privacyPolicies: {
                        ViewOnce: selectionViewOnce,
                        Expiration: selectionExpiration,
                        KeepOpenTimer: selectionKeepOpenTimer,
                    }
                });
                if (exifObj?.Exif) {
                    LogMe(1,'ExecuteTheMarking(): Exif exists in metadata');
                    exifObj['Exif'][piexif.ExifIFD.UserComment] = newValue;
                } else {
                    LogMe(1,'ExecuteTheMarking(): Exif DOES NOT exist in metadata');
                    exifObj = {...exifObj, 'Exif' : { [piexif.ExifIFD.UserComment] : [newValue]}};
                }
                LogMe(2,'exifObj modified: '+JSON.stringify(exifObj));
                LogMe(1,'ExecuteTheMarking(): piexif.dump');
                let exifBytes = piexif.dump(exifObj);
    
                LogMe(1,'ExecuteTheMarking(): piexif.insert');
                let dataContentsWithInsertedMetadata = await piexif.insert(exifBytes, dataUri);
                let base64ContentsWithInsertedMetadata = dataContentsWithInsertedMetadata.replace('data:image/'+fileExt+';base64,', '');
                LogMe(2,'ExecuteTheMarking(): base64ContentsWithInsertedMetadata: ----'+base64ContentsWithInsertedMetadata);
    
                // 
                LogMe(1,'ExecuteTheMarking(): Deleting/Writing to files');

                if (Platform.OS === 'android' && assets[i].albumId == privateAlbumID.key) {  
                    // The picture is in the PrivatePics album and it is an Androi device => we can update the
                    // files directly, rather than creating a new file. Caveat: Only works if this app instance
                    // created the file. If you rebuild the app from DEV to PROD this may raise a file
                    // permission error.
                    LogMe(1,'ExecuteTheMarking(): processing a picture that is in PrivatePics');
                    try {
                        await FileSystem.writeAsStringAsync(
                            hopefullyReadableUri,
                            base64ContentsWithInsertedMetadata,
                            {encoding: 'base64'}
                        );       
                    } catch (err) {
                        throw new Error('Error overwriting to an image file. This may happen if you marked the image with an app version deployed before migrating to a different type of workflow (bare/APK/AAB). Details: '+err.message);
                    }
                } else {  // The picture is NOT in the PrivatePics album
                    LogMe(1,'ExecuteTheMarking(): processing a picture that is NOT in PrivatePics');

                    let ImagePathTmp = FileSystem.documentDirectory + PARAM_PRIVATE_PICTURES_TMP_DIRNAME + '/' + uuid.v4() + '.' + fileExt;

                    LogMe(1,'ExecuteTheMarking(): writeAsStringAsync');
                    await FileSystem.writeAsStringAsync(ImagePathTmp, base64ContentsWithInsertedMetadata, {encoding: 'base64'});
                    LogMe(1, 'ExecuteTheMarking(): Tmp file saved to workspace: ' + ImagePathTmp); 
        
                    LogMe(1,'ExecuteTheMarking(): CameraRoll.saveAsset');
                    let retsave = await CameraRoll.saveAsset(ImagePathTmp, { type: 'photo', album: PARAM_PRIVATE_PICTURES_ALBUM_NAME } );
                }
    
                //await WriteMyFileStream(imageInCameraRoll.uri+'.temp.jpg', 'base64', false, base64ContentsWithInsertedMetadata);    
                /*
                await FileSystem.writeAsStringAsync(
                    imageInCameraRoll.uri+'.temp.jpg',
                    dataContentsWithInsertedMetadata.replace('data:image/'+fileExt+';base64,', ''),
                    {encoding: 'base64'}
                );
                await FileSystem.deleteAsync(imageInCameraRoll.uri, {idempotent: true});
                */    
            }
                
        } catch (err){
            ErrorAlert('Error while marking picture(s)', err);
        } finally {
            try {
                if (Platform.OS === 'android' && assets[i].albumId == privateAlbumID.key) {
                    // When the picture was in the PrivatePics album: Nothing to do
                } else {
                    await FileSystem.deleteAsync(ImagePathTmp, {idempotent: true});
                }
            } catch (err) {
                //ignored
            } finally {
                setAssets([]);
                setOpen(true);
                setIsProcessing(false);
            }
        }

        LogMe(1, 'ExecuteTheMarking(): Finished'); 

    } 

    useEffect( () => {  // This is executed when the component is reloaded
        async function didMount() { // Do not change the name of this function

            // Do stuff
            LogMe(1, 'useEffect of PPTagging invocation');  

            // See: https://stackoverflow.com/questions/38558200/react-setstate-not-updating-immediately
            // Warning: Despite not being formally an asynchronous function, setState is performed asynchronously
            // except if we access the state directly without its 'set' function and the value is a {} object:

            // Doint this in ComponentRefresh(); doesn't work
            LogMe(1, 'Requesting user permissions');

            let permsEIP = await ExpoImagePicker.requestMediaLibraryPermissionsAsync(); 
            LogMe(1, 'Result is: permsEIP='+JSON.stringify(permsEIP));
            if (permsEIP.granted) {
                LogMe(1, 'EIP perms granted');
            } else {
                LogMe(1, 'EIP perms not granted');
                await AsyncAlert('The system indicates that you did not grant privileges to access the pictures in the shared media library. This app needs this permission to operate. Please give the permissions by re-launching the app or by opening the system settings of your phone.');
            }      
/*
            let MLreqPerms = await MediaLibrary.requestPermissionsAsync();
            LogMe(1, 'Result is: MLreqPerms='+JSON.stringify(MLreqPerms));
            if (MLreqPerms.granted) {
                LogMe(1, 'ML req perms granted');
            } else {
                LogMe(1, 'ML req perms not granted');
                await AsyncAlert('The system indicates that you did not grant privileges to access the pictures in the shared media library. This app needs this permission to operate. Please give the permissions by re-launching the app or by opening the system settings of your phone.');
            }    
*/
            let MLusePerms = await usePermissions();
            LogMe(1, 'Result is: MLusePerms='+JSON.stringify(MLusePerms));
            if (MLusePerms.granted) {
                LogMe(1, 'ML use perms granted');
            } else {
                LogMe(1, 'ML use perms not granted');
                await AsyncAlert('The system indicates that you did not grant privileges to access the pictures in the shared media library. This app needs this permission to operate. Please give the permissions by re-launching the app or by opening the system settings of your phone.');
            }    

            if (permsEIP.granted && MLusePerms.granted) {
                setImagePermissionsGranted(true);       
            }

            LogMe(1, 'Refreshing PPTagging Component - completed');

        }

        didMount();  // If we want useEffect to be asynchronous, we have to define didMount as async and call it right after
        return async function didUnmount() { // Do not change the name of this function
          // Cleanup tasks
          LogMe(1, 'useEffect of PPTagging cleanup');
        };
    }, []);  // App.js does not have props

    async function ComponentRefresh() {  // Invoked every time this screen is loaded
        LogMe(1, 'Refreshing PPTagging Component');

        LogMe(1,'propsState.AccountData: '+JSON.stringify(propsState.AccountData));

        if (initStatus.key === 'init') {
            LogMe(1, 'Initialising PPTagging Component');
            initStatus.key = 'updated'; //update without rendering
            //initStatus({ key:'updated'}); //update with rendering
            // This will reach only on the first time the scren is loaded

            LogMe(1, 'on ComponentRefresh(), propsState.AccountData.firstrun: '+propsState.AccountData.firstrun);

            if (propsState.AccountData.firstrun) {

                await AsyncAlert(PARAM_WELCOME_MESSAGE);

                let cloneOfProps = {AccountData: propsState.AccountData};  // Force pass-by-value
                cloneOfProps.AccountData.firstrun = false;
        
                try {
                    await storage.save({
                        key: 'accountData', // Note: Do not use underscore("_") in key!
                        data: cloneOfProps.AccountData,
                    });
                } catch(error) { 
                    ErrorAlert(error.message, error);  // Storage error
                }
        
                setPropsState(cloneOfProps);    
            }
        }
    }

    const radioButtonsViewOnce = useMemo(() => ([
        {
            id: 'Yes', // acts as primary key, should be unique and non-empty string
            label: 'Yes',
        },
        {
            id: 'No',
            label: 'No',
        },
    ]), []);

    const radioButtonsExpiration = useMemo(() => ([
        {
            id: '15 minutes', // acts as primary key, should be unique and non-empty string
            label: '15 minutes',
        },
        {
            id: '3 hours',
            label: '3 hours',
        },
        {
            id: '3 days',
            label: '3 days',
        },
        {
            id: '90 days',
            label: '90 days',
        },
    ]), []);

    const radioButtonsKeepOpenTimer = useMemo(() => ([
        {
            id: '10 seconds', // acts as primary key, should be unique and non-empty string
            label: '10 seconds',
        },
        {
            id: '2 minutes',
            label: '2 minutes',
        },
        {
            id: '2 hours',
            label: '2 hours',
        },
    ]), []);

    // Initialisation
    ComponentRefresh();
    
    //We also load PPWrapComponent in the background to let it subscribe URL events when the app is already opened
    if (imagePermissionsGranted) {
        if (isProcessing) {
            return (
                <View style={styles.centercenterflex1}>
        
                    <View style={styles.headertitle}>
                        <Text style={styles.large}>Marking pictures as private</Text>
                    </View>
                    <View style={styles.centerleftflex1}>
                        <View style={styles.leftleft}>
                            <Text>       </Text>{/* Left margin */}
                        </View>
                        <View style={styles.centerleftflex1}>
                            <Text>{processingMessage}</Text>
                        </View>
                        <View style={styles.leftleft}>
                            <Text>       </Text>{/* Right margin */}
                        </View>
                    </View>
                    <TabsComponent activeTab="PPTagging" props={{propsState}} />
                </View>
            );
    
        } else {
            if (open) {
                return (
                    <View style={styles.centercenterflex1}>
            
                        <View style={styles.headertitle}>
                            <Text style={styles.large}>Marking pictures as private</Text>
                        </View>
                        <View style={styles.centerleftflex1}>
            
                            <ImagePicker
                                onSave={async(newassets) => {
                                    LogMe(1, 'onSave: '+JSON.stringify(newassets));
                                    setAssets(newassets);

                                    let hopefullyReadableUri;
                                    let uriWithExtension;
                                    if (Platform.OS === 'android') {
                                        hopefullyReadableUri = newassets[0].uri;
                                        uriWithExtension = newassets[0].uri;
                                    } else if (Platform.OS === 'ios') {
                                        hopefullyReadableUri = newassets[0].uri;
                                        uriWithExtension = (await MediaLibrary.getAssetInfoAsync(newassets[0])).localUri;
                                    } else {
                                        ErrorAlert('Platform not supported: '+Platform.OS);  
                                        return; 
                                    }    

                                    LogMe(2, "newassets[0]: "+JSON.stringify(newassets[0]));
                                    LogMe(2, "hopefullyReadableUri: "+hopefullyReadableUri);
                                    LogMe(2, "uriWithExtension: "+uriWithExtension);
                    
                                    // Load appropriate preselected values
                                    if (newassets.length == 1 // Only read privacy policies when there is 1 selected picture
                                        && 
                                        (
                                            (
                                                Platform.OS === 'android' && newassets[0].albumId == privateAlbumID.key
                                            )
                                            ||
                                            (
                                                Platform.OS === 'ios' && lastSelectedAlbumID.key == privateAlbumID.key
                                            ) // Unfortunately, iOS does not give the name or ID of the album of the selected picture(s)                        
                                        )
                                    ) {  // The selected picture is from the PrivatePics album, so we load its current privacy policies
                                        LogMe(1, 'Loading current values');
                                        let fileExt = uriWithExtension.split('.').pop().toLowerCase();
                                        if (fileExt=='jpg') { fileExt='jpeg' }  // piexif.insert() library replaces jpg by jpeg
                                        if (!IsValidImageExtensionAndContentType(fileExt)) {
                                            ErrorAlert('Image URI extension is not valid: '+fileExt);  
                                            return;                 
                                        } 
                                        if (fileExt!='jpeg' &&  fileExt!='tiff') {
                                            // Unsupported
                                            ErrorAlert('Image extension '+fileExt+' is not supported. Only jpg/jpeg and tiff images are supported.');
                                            return;
                                        }

                                        // iOS does not allow to read image files directly from the camera roll unless they are 
                                        // selected explicitly and individually with a native API (expo-image-multiple-picker uses 
                                        // loose permissions to massively access the image gallery)
                                        // Therefore, we work with a temporal copy
                                        let uriInCacheLoadPolicies = FileSystem.cacheDirectory + "/" + uuid.v4() + "." + fileExt;
                                        await FileSystem.copyAsync({
                                            from: hopefullyReadableUri,
                                            to: uriInCacheLoadPolicies,
                                        });

                                        let fileContentsOriginal = await FileSystem.readAsStringAsync(uriInCacheLoadPolicies, {encoding: 'base64'});

                                        await FileSystem.deleteAsync(uriInCacheLoadPolicies, {idempotent: true});

                                        let dataUri = 'data:image/'+fileExt+';base64,'+fileContentsOriginal;
                                        let exifObj = piexif.load(dataUri);
                                        LogMe(2,'exifObj: '+JSON.stringify(exifObj));

                                        if (exifObj?.Exif) {
                                            LogMe(1,'Checking if picture is actually marked as private: ExifIFD.UserComment exists in metadata: '+exifObj['Exif'][piexif.ExifIFD.UserComment]);
                                            try {
                                                LogMe(1, "Raw EXIF data: "+JSON.stringify(exifObj['Exif']));
                                                let metadataStr = exifObj['Exif'][piexif.ExifIFD.UserComment];
                                                metadataStr = metadataStr.replace(PARAM_EXIF_ASCII_PREFIX, '');
                                                metadata = JSON.parse(metadataStr);
                                                if (metadata?.pictureType === 'private') {
                                                    LogMe(1,'The picture is indeed private!');
                                                } else {
                                                    let msg = 'Inconsistency: Picture '+hopefullyReadableUri+' is in PrivatePics album but is not marked as private. Aborting.';
                                                    ErrorAlert(msg);
                                                    LogMe(1, msg);
                                                    return;
                                                }
                                                setSelectionViewOnce(metadata.privacyPolicies.ViewOnce);
                                                setSelectionExpiration(metadata.privacyPolicies.Expiration);
                                                setSelectionKeepOpenTimer(metadata.privacyPolicies.KeepOpenTimer);                                              
                                            } catch (exc) {
                                                let msg = 'Error parsing JPEG metadata. Possible another program is using the same field for other purposes. This error will be ignored. Error details: '+exc.message;
                                                ErrorAlert(msg);
                                                LogMe(1, msg);
                                                return;
                                            }
                                        } else {
                                            let msg = 'Inconsistency: Picture '+hopefullyReadableUri+' is in PrivatePics album but it does not have EXIF metadata. Aborting.';
                                            ErrorAlert(msg);
                                            LogMe(1, msg);
                                            return;
                                        }
                                    } else {
                                        LogMe(1, 'Setting `undefined` values');
                                        setSelectionViewOnce();
                                        setSelectionExpiration();
                                        setSelectionKeepOpenTimer();                                        
                                    }

                                    // Load appropriate informational message
                                    if (Platform.OS === 'android' && newassets[0].albumId == privateAlbumID.key) {
                                        setSelectionInfoMessage('The privacy policies of the selected private pictures will be updated with the following values:');
                                    } else {
                                        setSelectionInfoMessage('The selected pictures will be duplicated to the PrivatePics album, and marked as `private` with the following policies:');
                                    }

                                    // Load next screen
                                    setOpen(false);                            
                                }}
                                onCancel={() => {
                                    LogMe(1, 'onCancel');
                                }}
                                onChange={async(image, checked) => {
                                    LogMe(1, 'onChange');
                                }}
                                Albums
                                selected={assets}
                                multiple={true}
                                onSelectAlbum={(album) => {
                                    LogMe(1,'PPTagging: User selected album: '+JSON.stringify(album));
                                    lastSelectedAlbumID.key = album?.id;
                                    setAlbum(album);
                                    if (album?.title==PARAM_PRIVATE_PICTURES_ALBUM_NAME) {
                                        privateAlbumID.key = album?.id;
                                    }
                                }}
                                selectedAlbum={album}                            
                            />
            
                        </View>
                        <TabsComponent activeTab="PPTagging" props={{propsState}} />
                    </View>
                );    
            } else {
                return (
                    <View style={styles.centercenterflex1}>
                        <View style={styles.headertitle}>
                            <Text style={styles.large}>PRIVACY POLICIES</Text>
                        </View>
                        <View style={styles.centerleftflex1}>
                            <View style={styles.leftleft}>
                                <Text>       </Text>{/* Left margin */}
                            </View>
                            <View style={styles.centerleftflex1}>
                                <ScrollView style={styles.scrollView}>{/* ScrollView already expands, so we set their children not to expand, otherwise the buttons expand */}
                        
                                    <Text></Text>
                                    <Text>{selectionInfoMessage}</Text>
                                    <Text></Text>

                                    <Text>View only once</Text>
                                    <View style={styles.leftleft}>
                                        <Text style={styles.explanation}>When enabled, the recipient can only request to open the picture once.</Text>
                                    </View>
                                    <RadioGroup 
                                        radioButtons={radioButtonsViewOnce} 
                                        onPress={(selection) => {
                                            setSelectionViewOnce(selection)
                                        }}
                                        selectedId={selectionViewOnce}
                                        layout='row'
                                    />
            
                                    <Text />
            
                                    <Text>Expiration date</Text>
                                    <View style={styles.leftleft}>
                                        <Text style={styles.explanation}>From the time the picture is sent. After the configured expiration time, open requests will be refused.</Text>
                                    </View>
                                    <RadioGroup 
                                        radioButtons={radioButtonsExpiration} 
                                        onPress={(selection) => {
                                            setSelectionExpiration(selection)
                                        }}
                                        selectedId={selectionExpiration}
                                        containerStyle={styles.leftleftlist}
                                        layout='column'
                                    />
            
                                    <Text />
            
                                    <Text>Keep-open timer</Text>
                                    <View style={styles.leftleft}>
                                        <Text style={styles.explanation}>For a picture that has been opened, it will stay open in the screen for the configured time and the it will close automatically.</Text>
                                    </View>
                                    <RadioGroup 
                                        radioButtons={radioButtonsKeepOpenTimer} 
                                        onPress={(selection) => {
                                            setSelectionKeepOpenTimer(selection)
                                        }}
                                        selectedId={selectionKeepOpenTimer}
                                        containerStyle={styles.leftleftlist}
                                        layout='column'
                                    />
            
                                    <Text />

                                    <View style={styles.leftleft}>
                                    <Button title='PROCEED' onPress={() => {
                                        if (selectionViewOnce==undefined) {
                                            ErrorAlert('You must select a value for the `View Once`');
                                        } else if (selectionExpiration==undefined) {
                                            ErrorAlert('You must select a value for the `Expiration Timer`');
                                        } else if (selectionKeepOpenTimer==undefined) {
                                            ErrorAlert('You must select a value for the `Keep Open Timer`');
                                        } else {
                                            ExecuteTheMarking();
                                        }
                                     }}/>
                                    <Text>   </Text>
                                    <Button title='CANCEL' onPress={() => {
                                        setAssets([]);
                                        setOpen(true);
                                    }}/>
                                    </View>
            
                                </ScrollView>
                            </View>
                            <View style={styles.leftleft}>
                                <Text>       </Text>{/* Right margin */}
                            </View>
                        </View>
                        <TabsComponent activeTab="PPTagging" props={{propsState}} />
                    </View>
                );
            }
        }
    } else {
        return (
            <View style={styles.centercenterflex1}>
    
                <View style={styles.headertitle}>
                    <Text style={styles.large}>Marking pictures as private</Text>
                </View>
                <View style={styles.centerleftflex1}>
                    <View style={styles.leftleft}>
                        <Text>       </Text>{/* Left margin */}
                    </View>
                    <View style={styles.centerleftflex1}>
                        <Text>Awaiting user to grant permissions.</Text>
                    </View>
                    <View style={styles.leftleft}>
                        <Text>       </Text>{/* Right margin */}
                    </View>
                </View>
                <TabsComponent activeTab="PPTagging" props={{propsState}} />
            </View>
        );
    }

};
