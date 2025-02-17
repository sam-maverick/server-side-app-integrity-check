//import { StatusBar } from 'expo-status-bar';
import React, {useState, useCallback, useEffect, useRef, useMemo} from 'react';
import { StyleSheet, Button, Text, TextInput, View, Alert, ScrollView, Platform } from 'react-native';
import * as Device from 'expo-device';
import RNRestart from 'react-native-restart';  // Use only in PROD
import { DevSettings} from 'react-native';  // Use only in DEV
import Clipboard from '@react-native-clipboard/clipboard';

//import { useNavigation } from '@react-navigation/native';

import * as Integrity from 'expo-app-integrity';

import { TabsComponent } from './Tabs.jsx';

import { styles } from './myVisualsLibrary.jsx';
import { ErrorAlert, LogMe, UpdateLogMeUsername, InitialisationActions, DebugText, ClearDebugText } from '../myGeneralLibrary.jsx';

import * as storage from '../storage/storageApi.js';

import { ApiTestNetworkConnection } from '../network/networkApi.js';

import { useNavigation } from '@react-navigation/native';

import { PARAM_SHOW_EXTRA_INFO } from '../parameters.js';


var currentProps = undefined;


export const PPSettingsComponent = (props) => {

    LogMe(1, 'props of PPSettings: '+JSON.stringify(props));
    currentProps = props;
    const navigation = useNavigation();

    const [initStatus, setInitStatus] = useState({ key: 'init' });
    const [propsState, setPropsState] = useState(props.route.params);
    const [propsStateSync, setPropsStateSync] = useState({key: props.route.params});
    LogMe(1, 'propsState of PPSettings: '+JSON.stringify(propsState));

    const [networkStatus, setNetworkStatus] = useState('(press button)');
    const [storageDataShow, SetStorageDataShow] = useState();

    useEffect( () => {  // This is executed when the component is reloaded
        async function didMount() { // Do not change the name of this function
            // Do stuff
            LogMe(1, 'useEffect of PPSettings invocation');    
            const unsubscribe = navigation.addListener('focus', () => {
                // The screen is focused
                // Call any action
                LogMe(1, 'PPSettings: SCREEN FOCUS');
                setPropsState(currentProps.route.params);
                propsStateSync.key = currentProps.route.params;
                LogMe(1, 'props of PPSettings on Screen Focus event: '+JSON.stringify(currentProps));
            });                    
            try {
                SetStorageDataShow(JSON.stringify(propsStateSync.key));
            } catch(error) {
                SetStorageDataShow('Error / Empty');
            }       
        }
        didMount();  // If we want useEffect to be asynchronous, we have to define didMount as async and call it right after
        return async function didUnmount() { // Do not change the name of this function
          // Cleanup tasks
          LogMe(1, 'useEffect of PPSettings cleanup');
        };
    }, []);  // App.js does not have props


    async function ComponentRefresh() {  // Invoked every time this screen is loaded
        LogMe(1, 'Refreshing PPSettings Component');

        if (initStatus.key === 'init') {
            LogMe(1, 'Initialising PPSettings Component');
            initStatus.key = 'updated'; //update without rendering
            //initStatus({ key:'updated'}); //update with rendering
            // This will reach only on the first time the scren is loaded
        }
    }
    

    async function HandlerForLocalDataEraseFromSettings() {
        LogMe(1, 'HandlerForLocalDataEraseFromSettings()');
        try {
            //setCurrentScreenInMainComponent('PPReload');                    
            //setCurrentScreenInMainComponent('Register');  
            props.navigation.navigate('PPReload');
            await storage.deleteKey({ key: 'accountData', options: {} });
            await InitialisationActions();
            if (__DEV__) {
                DevSettings.reload(); // Only in DEV
            } else {
                RNRestart.restart();  // Only in PROD
            }
                  
        } catch(error) {
            //console.error(error);
            ErrorAlert(error.message, error);  // Some error
        }         
    }

    
    async function EraseLocalUserData() {
        Alert.alert('Confirmation', 'All your local data will be wiped. Are you sure you want to continue?', [
          {
            text: 'Cancel',
            //onPress: () => ,
            style: 'cancel',
          },
          {
            text: 'OK', onPress: async () => 
                {
                    await HandlerForLocalDataEraseFromSettings();        
                },
          },
        ]);
    }


    async function SaveAccountData(isUsername, fieldname, newdata) {
        let cloneOfProps = {AccountData: propsState.AccountData};  // Force pass-by-value
        cloneOfProps.AccountData[fieldname] = newdata;

        try {
            const storagenewdata = {
                key: 'accountData',
                value: cloneOfProps.AccountData,
                options: {},
            };
            await storage.save(storagenewdata);
            LogMe(1,'Saved to storage: '+JSON.stringify(storagenewdata));
        } catch(error) { 
            ErrorAlert(error.message, error);  // Storage error
        }

        setPropsState(cloneOfProps);
        
        if (isUsername)  { UpdateLogMeUsername(newdata); }
    }    


    async function CheckPPServer() {
        setNetworkStatus('Running test...');
        try {
            await ApiTestNetworkConnection();
        } catch(error) {
            //console.error(error);
            ErrorAlert("Error when sending application-level ping to the server", error);  // Network error
            setNetworkStatus('DOWN');
            return;
        }
        setNetworkStatus('OK');
    }


    // Initialisation
    ComponentRefresh();
    

    const ExtraInfoComponent = () => {
        if (PARAM_SHOW_EXTRA_INFO) {
            return(
                <View>    
                        <Text />
                        
                        <View style={styles.leftleft}>
                            <Text style={{fontWeight: "bold"}}>Username is: </Text>
                            <TextInput
                                style={styles.textfield}
                                onChangeText={newText => SaveAccountData(true, 'username', newText)}
                                defaultValue={propsState.AccountData.username}
                            />
                        </View>
                        <View style={styles.leftleft}>
                            <Text>Used only for debugging.</Text>
                        </View>
    
                        <Text />
    
                        <View style={styles.leftleft}>
                            <Text style={{fontWeight: "bold"}}>Is this a physical device? {Device.isDevice ? 'Yes' : 'No'}</Text>
                        </View>
                        <View style={styles.leftleft}>
                        <Text>Corresponds to Device.isDevice.</Text>
                        </View>
    
                        <Text />
    
                        <View style={styles.leftleft}>
                            <Text style={{fontWeight: "bold"}}>Platform OS is: {Platform.OS}</Text>
                        </View>
                        <View style={styles.leftleft}>
                        <Text>Corresponds to Platform.OS.</Text>
                        </View>
    
                        <Text />
    
                        <View style={styles.leftleft}>
                            <Text style={{fontWeight: "bold"}}>Platform version is: {Platform.Version}</Text>
                        </View>
                        <View style={styles.leftleft}>
                        <Text>Corresponds to Platform.Version.</Text>
                        </View>
    
                        <Text />
                        <View style={styles.leftleft}>
                            <Text style={{fontWeight: "bold"}}>Is this a development environment? {__DEV__ ? 'Yes' : 'No'}</Text>
                        </View>
    
                        <View style={styles.leftleft}>
                        <Text>Corresponds to __DEV__.</Text>
                        </View>
                        <View style={styles.leftleft}>
                        <Text>Used to trigger the appropriate app reload function. In Expo Go (say, development) we use DevSettings.reload(), whereas in the bare React Native app we use RNRestart.restart().</Text>
                        </View>
    
                        <Text />
    
                        <View style={styles.leftleft}>
                            <Text style={{fontWeight: "bold"}}>Storage data: </Text>
                        </View>
                        <View style={styles.leftleft}>
                            <Text>{ storageDataShow }</Text>
                        </View>
    
                        <Text />
                </View>
            );    
        }
    }



    return (
        <View style={styles.centercenterflex1}>
            <View style={styles.headertitle}>
                <Text style={styles.large}>Settings</Text>
            </View>
            <View style={styles.centerleftflex1}>
                <View style={styles.leftleft}>
                    <Text>       </Text>{/* Left margin */}
                </View>
                <View style={styles.centerleftflex1}>
                    <ScrollView style={styles.scrollView}>{/* ScrollView already expands, so we set their children not to expand, otherwise the buttons expand */}

                    <Text />
    
                        <View style={styles.leftleft}>
                            <Button title='Check PP server connection' onPress={() => CheckPPServer()} />
                        </View>

                        <View style={styles.leftleft}>
                            <Text>Network connection to PP server is: </Text><Text style={{fontWeight: "bold"}}>{ networkStatus }</Text>
                        </View>

                        <Text />

                        <View style={styles.leftleft}>
                            <Button title='Erase PP user data on this device' onPress={() => EraseLocalUserData()} />
                        </View>

                        <ExtraInfoComponent/>

                        <Text />

                        <View style={styles.leftleft}>
                        <Button title='Copy logs to clipboard' onPress={() => Clipboard.setString(DebugText)} />
                        </View>                        

                        <Text />

                        <View style={styles.leftleft}>
                        <Button title='Clear logs' onPress={ () => ClearDebugText() } />
                        </View>

                    </ScrollView>
                </View>
                <View style={styles.leftleft}>
                    <Text>       </Text>{/* Right margin */}
                </View>
            </View>
            <TabsComponent activeTab="PPSettings" props={{propsState}} />
        </View>
    );
};
