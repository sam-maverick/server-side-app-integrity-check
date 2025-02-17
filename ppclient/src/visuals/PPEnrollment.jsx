//import { StatusBar } from 'expo-status-bar';
import React, {useState, useCallback, useEffect, useRef} from 'react';
import { StyleSheet, Button, Text, TextInput, View, Alert, ScrollView, Platform, TouchableOpacity } from 'react-native';
import * as Device from 'expo-device';
import RNRestart from 'react-native-restart';  // Use only in PROD
import { DevSettings} from 'react-native';  // Use only in DEV

import AppLink from 'react-native-app-link';

import * as Integrity from 'expo-app-integrity';

import { TabsComponent } from './Tabs.jsx';

import { styles } from './myVisualsLibrary.jsx';
import { ErrorAlert, ErrorAlertAsync, LogMe, UpdateLogMeUsername, AsyncAlert } from '../myGeneralLibrary.jsx';

import * as storage from '../storage/storageApi.js';

import { 
    PARAM_GOOGLE_CLOUD_PROJECT_NUMBER, 
    PARAM_PP__IMAGEMARKER_APPNAME,
    PARAM_PP__IMAGEMARKER_IOSAPPID,
    PARAM_PP__IMAGEMARKER_IOSAPPSTORELOCALE,
    PARAM_PP__IMAGEMARKER_PLAYSTOREID,
    PARAM_PP__IMAGEMARKER_URL,
    PARAM_OVERRIDE_MODE,
    PARAM_SHOW_EXTRA_INFO_IN_SETTINGS,
 } from '../parameters.js';

import { ApiTestNetworkConnection } from '../network/networkApi.js';

import * as AppIntegrity from '../integrity/integrityapis.js';
 
import { DoWarmup, CheckIntegrity, DoKeygen } from '../integrity/integrityapis.js';

import { useNavigation } from '@react-navigation/native';



var currentProps = undefined;



export const PPEnrollmentComponent = (props) => {

    LogMe(1, 'props of PPEnrollment: '+JSON.stringify(props));
    currentProps = props;
    const navigation = useNavigation();

    const [initStatus, setInitStatus] = useState({ key: 'init' });
    const [propsState, setPropsState] = useState(props.route.params);
    const [propsStateSync, setPropsStateSync] = useState({ key: props.route.params });
    LogMe(1, 'propsState of PPEnrollment: '+JSON.stringify(propsState));
 
    // Internal state, only initialized when 
    const [internalSyncState, setInternalState] = useState({ attempted: false, completed: false });
    const [internalDummyState, setInternalDummyState] = useState();  // Used to force refresh

    // Test result
    const [lastResult, setLastResult] = useState('unknown');

    // Test related
    const [serverConnectionStatus, setServerConnectionStatus] = useState('--');
    const [savingStatus, setSavingStatus] = useState('--');

    const [androidWarmupStandardStatus, setAndroidWarmupStandardStatus] = useState('--');
    const [androidAttestationStandardStatus, setAndroidAttestationStandardStatus] = useState('--');
    const [androidAttestationClassicStatus, setAndroidAttestationClassicStatus] = useState('--');

    const [iosSupportStatus, setIosSupportStatus] = useState('--');
    const [iosKeypairStatus, setIosKeypairStatus] = useState('--');
    const [iosAttestationStatus, setIosAttestationStatus] = useState('--');
    const [iosAssertionStatus, setIosAssertionStatus] = useState('--');

    var callbackOnFinishFunction;
    if (props.callbackOnFinish!=undefined)  {
        callbackOnFinishFunction = props.callbackOnFinish;
        LogMe(1, 'callbackOnFinishFunction is: configured');
    } else {
        callbackOnFinishFunction = function () {};
        LogMe(1, 'callbackOnFinishFunction is: void');
    }


    async function SetIosKeyName(name) {
      
        //NO:internalSyncState.attempted = newState;

        let cloneOfProps = {AccountData: propsStateSync.key.AccountData};  // Force pass-by-value
        cloneOfProps.AccountData.iosKeyName = name;
        try {
            const storagenewdata = {
                key: 'accountData',
                value: cloneOfProps.AccountData,
                options: {},
            };
            await storage.save(storagenewdata);
            LogMe(1,'Saved to storage: '+JSON.stringify(name));

            setPropsState(cloneOfProps);
            propsStateSync.key = cloneOfProps;

        } catch(error) { 
            ErrorAlert(error.message, error);  // Storage error    
            LogMe(1, 'Storage issue.');
        }                                                    
    }

    async function SetAttempted(newState) {
      
        //NO:internalSyncState.attempted = newState;

        let cloneOfProps = {AccountData: propsStateSync.key.AccountData};  // Force pass-by-value
        cloneOfProps.AccountData.enrollmentAttempted = newState;
        try {
            const storagenewdata = {
                key: 'accountData',
                value: cloneOfProps.AccountData,
                options: {},
            };
            await storage.save(storagenewdata);
            LogMe(1,'Saved to storage: '+JSON.stringify(storagenewdata));

            setPropsState(cloneOfProps);
            propsStateSync.key = cloneOfProps;

            setLastResult('fail');

            callbackOnFinishFunction(false, props.requestedUrlParams);

        } catch(error) { 
            ErrorAlert(error.message, error);  // Storage error    
            LogMe(1, 'Storage issue.');
            callbackOnFinishFunction(false, props.requestedUrlParams);
        }                                                    
    }


    async function SetCompleted(newState) {

        //NO_internalSyncState.attempted = true;
        //NO:internalSyncState.completed = true;

        let cloneOfProps = {AccountData: propsStateSync.key.AccountData};  // Force pass-by-value
        // Cookies are already saved by CheckIntegrity()
        cloneOfProps.AccountData.enrollmentAttempted = newState;  
        cloneOfProps.AccountData.enrollmentCompleted = newState;  
        try {
            const storagenewdata = {
                key: 'accountData',
                value: cloneOfProps.AccountData,
                options: {},
            };
            await storage.save(storagenewdata);
            LogMe(1,'Saved to storage: '+JSON.stringify(storagenewdata));

            setPropsState(cloneOfProps);
            propsStateSync.key = cloneOfProps;

            setSavingStatus('Done');  // Successful

            setLastResult('success');

            callbackOnFinishFunction(true, props.requestedUrlParams);

        } catch(error) { 
            ErrorAlert(error.message, error);  // Storage error
            setSavingStatus('ERROR');        
            LogMe(1, 'Storage issue.');
            callbackOnFinishFunction(false, props.requestedUrlParams);
        }                                                    
    }


    async function Reattempt() {

        // Test result
        setLastResult('unknown');

        // Test related
        setServerConnectionStatus('--');
        setSavingStatus('--');

        setAndroidWarmupStandardStatus('--');
        setAndroidAttestationStandardStatus('--');
        setAndroidAttestationClassicStatus('--');

        setIosSupportStatus('--');
        setIosKeypairStatus('--');
        setIosAttestationStatus('--');
        setIosAssertionStatus('--');

        internalSyncState.attempted = false;

        setInternalDummyState('dummy data');  // Force refresh now

        AttemptEnrollment();
    }


    async function AttemptEnrollment() {
        LogMe(1, 'AttemptEnrollment()');
        LogMe(1, 'props.route.params: '+JSON.stringify(props.route.params));

        try {

            // Unless stated explicitly by our custom build parameter, we do not allow debug/emulated environments
            if (( ! PARAM_OVERRIDE_MODE) && (! Device.isDevice) ) {
                LogMe(1, 'Emulator detected');
                await SetAttempted(true);
                await ErrorAlertAsync('Running on an emulator is not allowed in production');
                return;
            }
 
            if (( ! PARAM_OVERRIDE_MODE) && __DEV__) { 
                LogMe(1, 'Debugging detected');
                await SetAttempted(true);
                await ErrorAlertAsync('Running with debugging enabled is not allowed in production');
                return;
            }

            await ApiTestNetworkConnection();

            setServerConnectionStatus('Successful');

            // ANDROID ------------------------------------------------------------------------------

            if (Platform.OS === 'android') {

                await AsyncAlert('Please go now to the app settings in the system configuration and make sure that the Privacy Provider permission is granted for the ppclient app before continuing. NOTE: If the permission does not appear, uninstall this ppclient app and the messaging app, and then make sure that the messaging app is installed BEFORE this ppclient app. Once verified, hit `Ok` to continue.', 'WARNING');
        
                await DoWarmup(setAndroidWarmupStandardStatus, function () {})
                .then( async (resultWarmup) => {
                
                    if (resultWarmup) {
                        LogMe(1, 'Warmup was successful');
                        CheckIntegrity('PPEnrollment', propsStateSync.key, function async (newProps) { propsStateSync.key = newProps; setPropsState(newProps); }, setAndroidAttestationStandardStatus, function () {}, 'standard', 'PPEcookie')
                        .then( async (resultStandard) => {

                            LogMe(1, 'after standard att. propsStateSync.key='+JSON.stringify(propsStateSync.key));

                            if (resultStandard) {
                                LogMe(1, 'Standard attestation was successful');
                                CheckIntegrity('PPEnrollment', propsStateSync.key, function async (newProps) { propsStateSync.key = newProps; setPropsState(newProps); }, setAndroidAttestationClassicStatus, function () {}, 'classic', 'PPEcookie')
                                .then( async (resultClassic) => {
    
                                    LogMe(1, 'after classic att. propsStateSync.key='+JSON.stringify(propsStateSync.key));

                                    if (resultClassic) {
                                        LogMe(1, 'Classic attestation was successful');


                                            SetCompleted(true);
                                              
                                            
                                    } else {
                                        await SetAttempted(true);
                                        LogMe(1, 'Classic attestation was unsuccessful');
                                    }
            
                                })
                                .catch( async(err) => {
                                    await SetAttempted(true);
                                    ErrorAlert(err.message, err);
                                    LogMe(1, 'Catch error: Classic attestation was unsuccessful');
                                });
                            } else {
                                await SetAttempted(true);
                                LogMe(1, 'Standard attestation was unsuccessful');
                            }
        
                        })
                        .catch( async(err) => {
                            await SetAttempted(true);
                            ErrorAlert(err.message, err);
                            LogMe(1, 'Catch error: Standard attestation was unsuccessful');
                        });

                    } else {
                        await SetAttempted(true);
                        LogMe(1, 'Warmup was unsuccessful');
                    }

                })
                .catch( async(err) => {
                    await SetAttempted(true);
                    ErrorAlert(err.message, err);
                    LogMe(1, 'Catch error: Warmup was unsuccessful');
                });



            // iOS ------------------------------------------------------------------------------

            } else if (Platform.OS === 'ios') {

                if (Integrity.isSupported()) {

                    setIosSupportStatus('OK');

                    await DoKeygen(setIosKeypairStatus, function () {})
                    .then( async (resultKeygen) => {
                    
                        if ( ! (resultKeygen===false)) {
                            LogMe(1, 'Key generation was successful');
                            LogMe(1, 'Key name is' + JSON.stringify(resultKeygen));

                            // store resultKeyken.something? as the key name for iosKeyName
                            await SetIosKeyName(resultKeygen);
                
                            CheckIntegrity('PPEnrollment', propsStateSync.key, function async (newProps) { propsStateSync.key = newProps; setPropsState(newProps); }, setIosAttestationStatus, function () {}, 'attestation', 'PPEcookie')
                            .then( async (resultAttestation) => {
    
                                if (resultAttestation) {
                                    LogMe(1, 'Attestation was successful');
                                    CheckIntegrity('PPEnrollment', propsStateSync.key, function async (newProps) { propsStateSync.key = newProps; setPropsState(newProps); }, setIosAssertionStatus, function () {}, 'assertion', 'PPEcookie')
                                    .then( async (resultAssertion) => {
        
                                        if (resultAssertion) {
                                            LogMe(1, 'Assertion was successful');
    
                       
                                                SetCompleted(true);
                                                            
    
                                        } else {
                                            await SetAttempted(true);
                                            LogMe(1, 'Assertion was unsuccessful');
                                        }
                
                                    })
                                    .catch( async(err) => {
                                        await SetAttempted(true);
                                        ErrorAlert(err.message, err);
                                        LogMe(1, 'Catch error: Assertion was unsuccessful');
                                    });
                                } else {
                                    await SetAttempted(true);
                                    LogMe(1, 'Attestation was unsuccessful');
                                }
            
                            })
                            .catch( async(err) => {
                                await SetAttempted(true);
                                ErrorAlert(err.message, err);
                                LogMe(1, 'Catch error: Attestation was unsuccessful');
                            });
    
                        } else {
                            await SetAttempted(true);
                            LogMe(1, 'Keygen was unsuccessful');
                        }
    
                    })
                    .catch( async(err) => {
                        await SetAttempted(true);
                        ErrorAlert(err.message, err);
                        LogMe(1, 'Catch error: Keygen was unsuccessful');
                    });

                } else {
                    // App Attest API not supported on this iOS device
                    await SetAttempted(true);
                }


            } else {
                // OS not supported
                setIosSupportStatus('Failed');
                await SetAttempted(true);
            }

        } catch(error) {
            setServerConnectionStatus('DOWN');
            await SetAttempted(true);
            ErrorAlert("Error when sending application-level ping to the server", error);  // Network error
        }
    }



    useEffect( () => {  // This is executed when the component is reloaded
        async function didMount() { // Do not change the name of this function

            // Do stuff
            LogMe(1, 'useEffect of PPEnrollment invocation');  

            // See: https://stackoverflow.com/questions/38558200/react-setstate-not-updating-immediately
            // Warning: Despite not being formally an asynchronous function, setState is performed asynchronously
            // except if we access the state directly without its 'set' function and the value is a {} object:

            const unsubscribe = navigation.addListener('focus', async () => {
                // The screen is focused
                // Call any action
                LogMe(1, 'PPEnrollment: SCREEN FOCUS');
                setPropsState(currentProps.route.params);
                propsStateSync.key = currentProps.route.params;
                LogMe(1, 'props of PPEnrollment on Screen Focus event: '+JSON.stringify(currentProps));
            });                    

            LogMe(2, 'propsState='+JSON.stringify(propsState));
            LogMe(2, 'propsStateSync.key='+JSON.stringify(propsStateSync.key));
            internalSyncState.attempted = propsState.AccountData.enrollmentAttempted;
            internalSyncState.completed = propsState.AccountData.enrollmentCompleted;
            setInternalDummyState('dummy data');
            LogMe(1, 'internalSyncState.attempted:'+internalSyncState.attempted);  
            LogMe(1, 'internalSyncState.completed:'+internalSyncState.completed);  

            if ( ! internalSyncState.attempted && ! internalSyncState.completed ) {

                await AttemptEnrollment();

            }

        }

        didMount();  // If we want useEffect to be asynchronous, we have to define didMount as async and call it right after
        return async function didUnmount() { // Do not change the name of this function
          // Cleanup tasks
          LogMe(1, 'useEffect of PPEnrollment cleanup');
        };
    }, []);  // App.js does not have props


    async function ComponentRefresh() {  // Invoked every time this screen is loaded
        LogMe(1, 'Refreshing PPEnrollment Component');
        if (initStatus.key === 'init') {
            LogMe(1, 'Initialising PPEnrollment Component');
            initStatus.key = 'updated'; //update without rendering
            //initStatus({ key:'updated'}); //update with rendering
            // This will reach only on the first time the scren is loaded
        }
    }
    
    async function OpenSettingsTab() {
        navigation.navigate('PPSettings', propsState);
    }

    async function OpenImageMarkerApp() { 
        await AppLink.maybeOpenURL(
            PARAM_PP__IMAGEMARKER_URL, 
            { 
            appName : PARAM_PP__IMAGEMARKER_APPNAME,
            appStoreId : PARAM_PP__IMAGEMARKER_IOSAPPID,
            appStoreLocale : PARAM_PP__IMAGEMARKER_IOSAPPSTORELOCALE,
            playStoreId : PARAM_PP__IMAGEMARKER_PLAYSTOREID,
            },
            async function(){ await AsyncAlert('You will be prompted to install the ppimagemarker app. Once installed, open the app and select the pictures you want to protect.', 'WARNING'); }
        );  // We need to pass a callback function to show the Alert, because Alerts are not shown when the app is in the background.
            // See: https://stackoverflow.com/questions/74662876/popup-alert-dialog-in-react-native-android-app-while-app-is-not-in-foreground
          
      LogMe(1, 'URL call to open has completed');
    }

    const CompletionInfoComponent = () => {
        if (lastResult=='success') {
            return(
                <View>
                    
                    <View style={styles.leftleft}>
                        <Text style={{fontWeight: "bold"}}>Enrollment successful!</Text>
                    </View>

                    <Text/>

                    <View style={styles.leftleft}>
                        <Text>NEXT STEPS:</Text>
                    </View>
                    <Text/>

                    <StepsComponent/>

                </View>
            );
        } else {
            return(
                <View>
                    <View style={styles.leftleft}>
                        <Text style={{fontWeight: "bold"}}>Enrollment unsuccessful :-/</Text>
                    </View>

                    <Text/>

                    <View style={styles.leftleft}>
                        <ReattemptButtonComponent />
                    </View>

                </View>
            );
        }
    }

    const StepsComponent = () => {
        return(
            <View>
                <View style={styles.leftleft}>
                    <Text>1. Mark as 'private' the pictures you want to protect, using the <Text style={styles.link} onPress={OpenImageMarkerApp}>ppimagemarker app</Text>, and establish their privacy policies.</Text>
                </View>
                <Text/>
                <View style={styles.leftleft}>
                    <Text>2. In your messaging app, pictures shared from the PrivatePics album will be protected by your Privacy Provider.</Text>
                </View>
            </View>
        );
    }

    const CompletionComponent = () => {
        return(
            <View style={{opacity: ( lastResult == 'unknown' ? 0 : 100 ) }}>

            <Text />

            <CompletionInfoComponent />

            <Text />

            </View>
        );
    }


    const ReattemptButtonComponent = () => {
        return(
            <View style={styles.leftleft}>
                <Button title='Reattempt enrollment' onPress={() => Reattempt() } />
            </View>
        );
    }

    const ReEnrollComponent = () => {
        if (PARAM_SHOW_EXTRA_INFO_IN_SETTINGS) {
            return(
                <View>
                    <View style={styles.leftleft}>
                        <Text>If you want to re-enroll, delete the local data by using the Settings option of this app, or reinstall the app. Re-enroll only if absolutely necessary, as there are security limits on the number of times that a device can re-enroll.</Text>
                    </View>

                    <Text/>                    
                </View>
            );    
        }
    }

    const EnrollmentMainComponent = () => {

            if (internalSyncState.completed) {
                return(
                    <View>
                        <Text />
    
                        <View style={styles.leftleft}>
                            <Text style={{fontWeight: "bold"}}>This device is already enrolled.</Text>
                        </View>
    
                        <Text/>
    
                        <ReEnrollComponent/>

                        <View style={styles.leftleft}>
                            <Text>This is how you use the security and privacy features provided by this app:</Text>
                        </View>
                        <Text/>
                        <StepsComponent/>
                        
                    </View>
                );
            } else if (internalSyncState.attempted) {  // Attempted in a prior run but not completed
                return(
                    <View>
                        <Text />

                        <View style={styles.leftleft}>
                            <Text style={{fontWeight: "bold"}}>The prior enrollment attempt was unsuccessful.</Text>
                        </View>

                        <Text/>

                        <View style={styles.leftleft}>

                            <ReattemptButtonComponent />

                        </View>
                    </View>
                );
            } else { // Not attempted, not completed
                if (Platform.OS === 'android') {
                    return(
                        <View>
                            <Text />
                            <Text style={{fontWeight: "bold"}}>PERFORMING AUTO-ENROLLMENT</Text>
                            <Text />
    
                            <View style={styles.leftleft}>
                                <Text>Connection to PP server: </Text><Text style={{fontWeight: "bold"}}>{ serverConnectionStatus }</Text>
                            </View>
    
                            <View style={styles.leftleft}>
                                <Text>Warmup for standard attestation: </Text><Text style={{fontWeight: "bold"}}>{ androidWarmupStandardStatus }</Text>
                            </View>
        
                            <View style={styles.leftleft}>
                                <Text>Standard attestation test: </Text><Text style={{fontWeight: "bold"}}>{ androidAttestationStandardStatus }</Text>
                            </View>
        
                            <View style={styles.leftleft}>
                                <Text>Classic attestation test: </Text><Text style={{fontWeight: "bold"}}>{ androidAttestationClassicStatus }</Text>
                            </View>
    
                            <View style={styles.leftleft}>
                                <Text>Saving data: </Text><Text style={{fontWeight: "bold"}}>{ savingStatus }</Text>
                            </View>
    
                            <CompletionComponent/>
    
                        </View>
                    );
                } else if (Platform.OS === 'ios') {
                    return(
                        <View>
                            <Text />
                            <Text style={{fontWeight: "bold"}}>PERFORMING AUTO-ENROLLMENT</Text>
                            <Text />
        
                            <View style={styles.leftleft}>
                                <Text>Connection to PP server: </Text><Text style={{fontWeight: "bold"}}>{ serverConnectionStatus }</Text>
                            </View>
    
                            <View style={styles.leftleft}>
                                <Text>Compatibility verification: </Text><Text style={{fontWeight: "bold"}}>{ iosSupportStatus }</Text>
                            </View>
        
                            <View style={styles.leftleft}>
                                <Text>Key-pair generation: </Text><Text style={{fontWeight: "bold"}}>{ iosKeypairStatus }</Text>
                            </View>
        
                            <View style={styles.leftleft}>
                                <Text>Attestation: </Text><Text style={{fontWeight: "bold"}}>{ iosAttestationStatus }</Text>
                            </View>
        
                            <View style={styles.leftleft}>
                                <Text>Assertion test: </Text><Text style={{fontWeight: "bold"}}>{ iosAssertionStatus }</Text>
                            </View>
    
                            <View style={styles.leftleft}>
                                <Text>Saving data: </Text><Text style={{fontWeight: "bold"}}>{ savingStatus }</Text>
                            </View>
    
                            <CompletionComponent/>
    
                        </View>
                    );
                } else {
                    return(
                        <View>
                            <Text />
        
                            <View style={styles.leftleft}>
                                <Text style={{fontWeight: "bold"}}>Your platform is not supported. Only 'android' and 'ios' platforms are supported.</Text>
                            </View>
                        </View>
                    );
                }  
            }    
    };


    // Initialisation
    ComponentRefresh();
    
    //We also load PPWrapComponent in the background to let it subscribe URL events when the app is already opened
    return (
        <View style={styles.centercenterflex1}>

            <View style={styles.headertitle}>
                <Text style={styles.large}>Enrollment procedure</Text>
            </View>
            <View style={styles.centerleftflex1}>
                <View style={styles.leftleft}>
                    <Text>       </Text>{/* Left margin */}
                </View>
                <View style={styles.centerleftflex1}>
                    <ScrollView style={styles.scrollView}>{/* ScrollView already expands, so we set their children not to expand, otherwise the buttons expand */}

                        <EnrollmentMainComponent />

                        <Text />

                    </ScrollView>
                </View>
                <View style={styles.leftleft}>
                    <Text>       </Text>{/* Right margin */}
                </View>
            </View>
            <TabsComponent activeTab="PPEnrollment" props={{propsState}} />
        </View>
    );
};
