//import { StatusBar } from 'expo-status-bar';
import React, {useState, useCallback, useEffect, useRef} from 'react';
import { StyleSheet, Button, Text, TextInput, View, Alert, ScrollView, Platform } from 'react-native';
import * as Device from 'expo-device';
import RNRestart from 'react-native-restart';  // Use only in PROD
import { DevSettings} from 'react-native';  // Use only in DEV
import Clipboard from '@react-native-clipboard/clipboard';

import { styles } from './myVisualsLibrary.jsx';
import { EraseLocalData, ErrorAlert, LogMe, DebugText, ClearDebugText } from '../myGeneralLibrary.jsx';
import { TabsComponent } from './Tabs.jsx';

import storage from '../storage/storageApi.js';

import { ApiResetFactoryDB } from '../network/networkApi.js';




export const SettingsComponent = props => {

    const [initStatus, setInitStatus] = useState({ key: 'init' });
    const [debugText, setDebugText] = useState(DebugText);

    useEffect( () => {  // This is executed when the app is launched
        async function didMount() { // Do not change the name of this function
            // Do stuff
            LogMe(1, 'useEffect of Settings invocation');           
        }
        didMount();  // If we want useEffect to be asynchronous, we have to define didMount as async and call it right after
        return async function didUnmount() { // Do not change the name of this function
          // Cleanup tasks
          LogMe(1, 'useEffect of Settings cleanup');
        };
    }, []);  // App.js does not have props


    async function ComponentRefresh() {  // Invoked every time this screen is loaded
        LogMe(1, 'Refreshing Settings Component');

        if (initStatus.key === 'init') {
            LogMe(1, 'Initialising Settings Component');
            initStatus.key = 'updated'; //update without rendering
            //initStatus({ key:'updated'}); //update with rendering
            // This will reach only on the first time the scren is loaded
        }
    }
    

    function setCurrentScreenInMainComponent(newState) {
        props.setCurrentScreenInCurrentComponent(newState);
    }


    async function HandlerForLocalDataEraseFromSettings() {
        LogMe(1, 'HandlerForLocalDataEraseFromSettings()');
        try {
            await EraseLocalData();
            if (__DEV__) {
                DevSettings.reload(); // Only in DEV
            } else {
                RNRestart.restart();  // Only in PROD
            }
            setCurrentScreenInMainComponent('WaitReload');                    
            //setCurrentScreenInMainComponent('Register');                    
        } catch(error) {
            //console.error(error);
            ErrorAlert(error.message, error);  // Some error
        }         
    }


    async function EraseAllServerData() {
        LogMe(1, 'EraseAllServerData()');
        Alert.alert('Confirmation', 'All user data on the server side, as well as the app\'s local data, will be erased. All other client apps will have to be restarted. Are you sure you want to continue?', [
          {
            text: 'Cancel',
            //onPress: () => ,
            style: 'cancel',
          },
          {
            text: 'OK', onPress: async () => 
                {
                    try {
                        let res = await ApiResetFactoryDB();
                        if (!res.isSuccessful) {
                            ErrorAlert('An error has occurred on the server. Check the server and try again.');  // Network error
                        } else {
                            await HandlerForLocalDataEraseFromSettings();                    
                        }
                    } catch(error) {
                        //console.error(error);
                        ErrorAlert(error.message, error);  // Network error
                    }        
                },
          },
        ]);    
    }


    
    async function EraseLocalUserData() {
        Alert.alert('Confirmation', 'All your chat history will be permanently lost, your account will be permanently locked, and you will have to register a new account. Are you sure you want to continue?', [
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


    // Initialisation
    ComponentRefresh();
    
    
    return (
        <View style={styles.centercenterflex1}>
            <View style={styles.headertitle}>
                <Text style={styles.large}>Global settings</Text>
            </View>
            <View style={styles.centerleftflex1}>
                <View style={styles.leftleft}>
                    <Text>       </Text>{/* Left margin for the Settings items */}
                </View>
                <View style={styles.centerleftflex1}>
                    <ScrollView style={styles.scrollView}>{/* ScrollView already expands, so we set their children not to expand, otherwise the buttons expand */}

                        <View style={styles.leftleft}>
                            <Text style={styles.enormous}>Your username is: </Text><Text style={styles.usernamestyle}>{props.AccountData.username}</Text>
                        </View>

                        <Text />

                        <View style={styles.leftleft}>
                            <Button title='Erase user data on this device' onPress={() => EraseLocalUserData()} />
                        </View>

                        <Text />

                        <View style={styles.leftleft}>
                            <Button title='Erase all server data' onPress={() => EraseAllServerData()} />
                        </View>

                        <Text />

                        <View style={styles.leftleft}>
                            <Text style={{fontWeight: "bold"}}>Is this a physical device? {Device.isDevice ? 'Yes' : 'No'}</Text>
                        </View>
                        <View style={styles.leftleft}>
                        <Text>Corresponds to Device.isDevice.</Text>
                        </View>
                        <View style={styles.leftleft}>
                        <Text>Used to set a special fixed loopback address for the server, when running locally as an AVD or emulator.</Text>
                        </View>
                        <View style={styles.leftleft}>
                        <Text>Used in parameters.js.</Text>
                        </View>

                        <Text />

                        <View style={styles.leftleft}>
                            <Text style={{fontWeight: "bold"}}>Platform OS is: {Platform.OS}</Text>
                        </View>
                        <View style={styles.leftleft}>
                        <Text>Corresponds to Platform.OS.</Text>
                        </View>
                        <View style={styles.leftleft}>
                        <Text>Used for safeview.paddingTop, and is used to prevent our UI from overlapping the top bar of icons.</Text>
                        </View>
                        <View style={styles.leftleft}>
                        <Text>Used in myVisualsLibrary.jsx.</Text>
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
                        <View style={styles.leftleft}>
                        <Text>Used in Settings.jsx and App.js.</Text>
                        </View>

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
            </View>
            <TabsComponent setCurrentScreenInTabsComponent={setCurrentScreenInMainComponent} activeTab="Settings" />
        </View>
    );
};
