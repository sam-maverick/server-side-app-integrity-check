//import { StatusBar } from 'expo-status-bar';
import React, {useState, useCallback, useEffect, useRef} from 'react';
import { StyleSheet, Button, Text, TextInput, View, Alert, ScrollView, Platform } from 'react-native';
import * as Device from 'expo-device';
import RNRestart from 'react-native-restart';  // Use only in PROD
import { DevSettings} from 'react-native';  // Use only in DEV

import * as Integrity from 'expo-app-integrity';

import { TabsComponent } from './Tabs.jsx';

import { styles } from './myVisualsLibrary.jsx';
import { ErrorAlert, LogMe, UpdateLogMeUsername } from '../myGeneralLibrary.jsx';

import * as storage from '../storage/storageApi.js';

//import {  } from '../parameters.js';

import { useNavigation } from '@react-navigation/native';

import { DoKeygen, DoWarmup, CheckIntegrity } from '../integrity/integrityapis.js';



var currentProps = undefined;

export const PPIntegrityComponent = (props) => {

    LogMe(1, 'props of PPIntegrity: '+JSON.stringify(props));
    currentProps = props;
    const navigation = useNavigation();

    const [initStatus, setInitStatus] = useState({ key: 'init' });
    const [propsState, setPropsState] = useState(props.route.params);
    const [propsStateSync, setPropsStateSync] = useState({ key: props.route.params });
    LogMe(1, 'propsState of PPIntegrity: '+JSON.stringify(propsState));

    // Android (classic attestations) and iOS
    const [attestationStatus, setAttestationStatus] = useState('(press button)');
    const [attestationTestInProgress, setAttestationTestInProgress] = useState(false);

    // Only in Android
    const [attestationStatusStandard, setAttestationStatusStandard] = useState('(press button)');
    const [attestationTestInProgressStandard, setAttestationTestInProgressStandard] = useState(false);
    const [warmupStatusStandard, setWarmupStatusStandard] = useState('(press button)');
    const [warmupInProgressStandard, setWarmupInProgressStandard] = useState(false);

    // Only in iOS
    const [keygenInProgress, setkeygenInProgress] = useState(false);
    const [keygenStatus, setkeygenStatus] = useState('(press button)');
    const [assertionInProgress, setAssertionInProgress] = useState(false);
    const [assertionStatus, setAssertionStatus] = useState('(press button)');


    useEffect( () => {  // This is executed when the component is reloaded
        async function didMount() { // Do not change the name of this function
            // Do stuff
            LogMe(1, 'useEffect of PPIntegrity invocation');   
            const unsubscribe = navigation.addListener('focus', () => {
                // The screen is focused
                // Call any action
                LogMe(1, 'PPIntegrity: SCREEN FOCUS');
                setPropsState(currentProps.route.params);
                propsStateSync.key = currentProps.route.params;
                LogMe(1, 'props of PPIntegrity on Screen Focus event: '+JSON.stringify(currentProps));
            });                    
        }
        didMount();  // If we want useEffect to be asynchronous, we have to define didMount as async and call it right after
        return async function didUnmount() { // Do not change the name of this function
          // Cleanup tasks
          LogMe(1, 'useEffect of PPIntegrity cleanup');
        };
    }, []);  // App.js does not have props


    async function ComponentRefresh() {  // Invoked every time this screen is loaded
        LogMe(1, 'Refreshing PPIntegrity Component');
        if (initStatus.key === 'init') {
            LogMe(1, 'Initialising PPIntegrity Component');
            initStatus.key = 'updated'; //update without rendering
            //initStatus({ key:'updated'}); //update with rendering
            // This will reach only on the first time the scren is loaded
        }
    }



    const IntegrityInfoComponentIos = () => {
        if (Platform.OS === 'ios') {
            return(
                <View>
                    <Text />

                    <View style={styles.leftleft}>
                        <Text style={{fontWeight: "bold"}}>Is App Integrity supported in this iOS device? {Integrity.isSupported() ? 'Yes' : 'No'}</Text>
                    </View>
                    <View style={styles.leftleft}>
                    <Text>Corresponds to Integrity.isSupported().</Text>
                    </View>
                </View>
            );
        } else {
            return;
        }     
    };


    const WarmupInfoComponentAndroid = () => {
        if (Platform.OS === 'android') {
            return(
                <View>
                    <Text />

                    <View style={styles.leftleft}>
                        <Button disabled={warmupInProgressStandard} title='Do warmup now' onPress={() => DoWarmup(setWarmupStatusStandard, setWarmupInProgressStandard)} />
                    </View>
                    <View style={styles.leftleft}>
                        <Text>Warmup result is: </Text><Text style={{fontWeight: "bold"}}>{ warmupStatusStandard }</Text>
                    </View>

                    <View style={styles.leftleft}>
                    <Text>This only applies to standard requests in Android. API limits: Maximum 5 warmups per app instance per minute (if this threshold is exceeded, you will get a TOO_MANY_REQUESTS error). Note that if you set MAX_PARTIAL_DELAY_MS_STANDARD to less than one minute, and if you hit the Warmup button more than 5 times consecutively and then wait MAX_PARTIAL_DELAY_MS_STANDARD, you will find yourself temporarily unable to perform classic requests (temporary lockout).</Text>
                    </View>
                </View>
            );
        } else {
            return;
        }     
    };


    const StandardRequestComponentAndroid = () => {
        if (Platform.OS === 'android') {
            return(
                <View>
                    <Text />

                    <View style={styles.leftleft}>
                        <Button disabled={attestationTestInProgressStandard} title='Check integrity (standard request)' onPress={() => CheckIntegrity('PPIntegrity', propsStateSync.key, function async (newProps) { LogMe(1, 'newProps='+JSON.stringify(newProps)); propsStateSync.key = newProps; setPropsState(newProps); }, setAttestationStatusStandard, setAttestationTestInProgressStandard, 'standard', 'PPIcookie')} />
                    </View>

                    <View style={styles.leftleft}>
                        <Text>This attestation is based on a hash of the intended user action. Note that the attested timestampMillis of the token corresponds to the time when the warmup was performed. This attestation contains security metrics. API limits: Maximum 10,000 requests per app platform per day ('requests' includes warmups and integrity tokens).</Text>
                    </View>
                    <View style={styles.leftleft}>
                        <Text>Attestation status is: </Text><Text style={{fontWeight: "bold"}}>{ attestationStatusStandard }</Text>
                    </View>
                </View>
            );
        } else {
            return;
        }     
    };

    
    const ClassicOrIosAttestRequestComponent = () => {
        if (Platform.OS === 'android' || Platform.OS === 'ios') {
            return(
                <View>
                    <Text />

                    <View style={styles.leftleft}>
                        {
                            Platform.OS === 'android'
                            ?
                            <Button disabled={attestationTestInProgress} title="Check integrity (classic request)" onPress={() => CheckIntegrity('PPIntegrity', propsStateSync.key, function async (newProps) { propsStateSync.key = newProps; setPropsState(newProps); }, setAttestationStatus, setAttestationTestInProgress, 'classic', 'PPIcookie')} />
                            :
                            <Button disabled={attestationTestInProgress} title="Do attestation" onPress={() => CheckIntegrity('PPIntegrity', propsStateSync.key, function async (newProps) { LogMe(1, 'newProps='+JSON.stringify(newProps)); propsStateSync.key = newProps; setPropsState(newProps); }, setAttestationStatus, setAttestationTestInProgress, 'attestation', 'PPIcookie')} />
                        }
                    </View>

                    <View style={styles.leftleft}>
                        <Text>This attestation is nonce-based.</Text>
                    </View>
                    <View style={styles.leftleft}>
                        <Text>{ 
                            Platform.OS === 'android'
                            ?
                            'This attestation does NOT contain security metrics. API limits: Maximum 5 integrity tokens per app instance per minute; and maximum 10,000 requests per app platform per day (an increase can be requested)'
                            :
                            'This attestation contains security metrics. In iOS, attestations are done typically only once after installing the app.'
                        }</Text>
                    </View>
                    <View style={styles.leftleft}>
                        <Text>Attestation status is: </Text><Text style={{fontWeight: "bold"}}>{ attestationStatus }</Text>
                    </View>
                </View>
            );
        } else {
            return(
                <View>
                    <Text />

                    <View style={styles.leftleft}>
                        <Text style={{fontWeight: "bold"}}>Attestation is only supported in Android or iOS devices. Skipping Classic/iOS attestation. This device is {Platform.OS}.</Text>
                    </View>
                </View>
            );
        }     
    };
        

    const KeypairInfoComponentIos = () => {
        if (Platform.OS === 'ios') {
            return(
                <View>
                    <Text />

                    <View style={styles.leftleft}>
                        <Button disabled={keygenInProgress} title='Generate new key-pair' onPress={async() => {
                            let name = await DoKeygen(setkeygenStatus, setkeygenInProgress);

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

                        }}
                        />
                    </View>
                    <View style={styles.leftleft}>
                        <Text>Keygen result is: </Text><Text style={{fontWeight: "bold"}}>{ keygenStatus }</Text>
                    </View>

                    <View style={styles.leftleft}>
                        <Text>Key-pair name ('' means none):</Text>
                    </View>
                    <View style={styles.leftleft}>
                        <Text style={{fontWeight: "bold"}}>{propsState.AccountData.iosKeyName}</Text>
                    </View>
                    <View style={styles.leftleft}>
                    <Text>This only applies to iOS.</Text>
                    </View>
                </View>
            );
        } else {
            return;
            /*
            return(
                <View>
                    <Text />

                    <View style={styles.leftleft}>
                        <Text style={{fontWeight: "bold"}}>Non-ios device detected. Skipping key-pair generation/retrieval.</Text>
                    </View>
                </View>
            );
            */
        }     
    };


    const IosAssertionComponent = () => {
        if (Platform.OS === 'ios') {
            return(
                <View>
                    <Text />

                    <View style={styles.leftleft}>
                        <Button disabled={assertionInProgress} title='Do assertion' onPress={() => CheckIntegrity('PPIntegrity', propsStateSync.key, function async (newProps) { LogMe(1, 'newProps='+JSON.stringify(newProps)); propsStateSync.key = newProps; setPropsState(newProps); }, setAssertionStatus, setAssertionInProgress, 'assertion', 'PPIcookie')} />
                    </View>
                    <View style={styles.leftleft}>
                        <Text>Assertion result is: </Text><Text style={{fontWeight: "bold"}}>{ assertionStatus }</Text>
                    </View>

                    <View style={styles.leftleft}>
                        <Text>Do we hold an attested key-pair? </Text>
                        <Text style={{fontWeight: "bold"}}>{propsState.AccountData.iosKeyName==='' ? 'No' : 'Yes'}</Text>
                    </View>
                    <View style={styles.leftleft}>
                    <Text>This only applies to iOS.</Text>
                    </View>
                </View>
            );
        } else {
            return;
        }     
    };


    // Initialisation
    ComponentRefresh();
    
    
    return (
        <View style={styles.centercenterflex1}>
            <View style={styles.headertitle}>
                <Text style={styles.large}>Manual integrity tests</Text>
            </View>
            <View style={styles.centerleftflex1}>
                <View style={styles.leftleft}>
                    <Text>       </Text>{/* Left margin */}
                </View>
                <View style={styles.centerleftflex1}>
                    <ScrollView style={styles.scrollView}>{/* ScrollView already expands, so we set their children not to expand, otherwise the buttons expand */}

                        <IntegrityInfoComponentIos/>

                        <WarmupInfoComponentAndroid/>

                        <KeypairInfoComponentIos/>

                        <StandardRequestComponentAndroid/>

                        <ClassicOrIosAttestRequestComponent/>

                        <IosAssertionComponent/>

                        <Text />

                    </ScrollView>
                </View>
                <View style={styles.leftleft}>
                    <Text>       </Text>{/* Right margin */}
                </View>
            </View>
            <TabsComponent activeTab="PPIntegrity" props={{propsState}} />
        </View>
    );
};
