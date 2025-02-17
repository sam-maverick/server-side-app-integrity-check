//import { StatusBar } from 'expo-status-bar';
import React, {useState, useCallback, useEffect, useRef} from 'react';
import { StyleSheet, Button, Text, TextInput, View, SafeAreaView, Alert } from 'react-native';
import RNRestart from 'react-native-restart';  // Use only in PROD
import { DevSettings } from 'react-native';  // Use only in DEV
import { LogBox } from 'react-native';

import Storage from 'react-native-storage';
//import AsyncStorage from '@react-native-async-storage/async-storage';

// We need this to let the PrivatePictureAPI register the Linking.addEventListener at boot time, 
// otherwise this error is raised: 
// TypeError: Cannot read property 'NativeModule' of undefined, js engine: hermes
import * as PrivatePictureAPI from '../os_update/PrivatePictureAPI.js';
import * as FileSystem from 'expo-file-system';
import { registerRootComponent } from 'expo';


import { PARAM_IMAGES_DIRNAME } from './parameters.js';

import { styles } from './visuals/myVisualsLibrary.jsx';
import { EraseLocalData, ErrorAlert, AsyncErrorAlert, InitialisationActions, LogMe, UpdateLogMeUsername } from './myGeneralLibrary.jsx';

import storage from './storage/storageApi.js';

import { TabsComponent } from './visuals/Tabs.jsx';
import { SettingsComponent } from './visuals/Settings.jsx';
import { ChatsComponent } from './visuals/Chats.jsx';
import { RegisterComponent } from './visuals/Register.jsx';
import { PrivateChatComponent } from './visuals/PrivateChat.jsx';

import { ApiCheckAccount } from './network/networkApi.js';


LogBox.ignoreLogs([
    "Overwriting fontFamily style attribute preprocessor"
  ]);
 


export default function App() {

    const [currentScreen, setCurrentScreen] = useState('Init');  // Changing this state triggers a component refresh
    const [AccountData, setAccountData] = useState({});
    const [openedPrivateChat, setOpenedPrivateChat] = useState('Init');

    /*
    NOTE:
    These are some particularities of useEffect in App.js (the app's entry point), compared to other components:
    - There is no props.
    - It is called just once, when the app is launched.
    */
    useEffect( () => {  // This is executed when the app is launched
        async function didMount() { // Do not change the name of this function
            // Do stuff
            LogMe(1, 'useEffect of App invocation');
            await InitialisationActions();            
        }
        didMount();  // If we want useEffect to be asynchronous, we have to define didMount as async and call it right after
        return async function didUnmount() { // Do not change the name of this function
          // Cleanup tasks
          LogMe(1, 'useEffect of App cleanup');
        };
    }, []);  // App.js does not have props



    // This is executed whenever the currentScreen is changed
    async function ComponentRefresh() {    
        LogMe(1, 'Refreshing App Component');

        if (currentScreen === 'Init') {   
        
            LogMe(1, 'Initialising App Component');

            try {

                let retStorage = await storage.load({
                    syncInBackground: false,        
                    key: 'accountData',
                });

                LogMe(1, 'retStorage='+JSON.stringify(retStorage));
                // Note: when using the the bare workflow, old data may reappear. This should not happen with the APK/standalone workflow
                    
                try {
                 
                    let resApi = await ApiCheckAccount(retStorage.cookie);

                    if (!resApi.isSuccessful && resApi.resultMessage==='Cookie not found on the server.') {
                        await AsyncErrorAlert('Sorry, your account was not found on the server. Probably, the DB has been reset. Your local chat history will be deleted and you will have to register again.');
 
                        try {
                            await EraseLocalData();
                            if (__DEV__) {
                                DevSettings.reload(); // Only in DEV
                            } else {
                                RNRestart.restart();  // Only in PROD
                            }
                            setCurrentScreen('WaitReload');
                            //setCurrentScreen('Register');
                        } catch(error) {
                            //console.error(error);
                            ErrorAlert(error.message, error);  // some error
                        }        

                    } else {
                        setAccountData({'username': retStorage.username, 'cookie': retStorage.cookie});
                        UpdateLogMeUsername(retStorage.username);
                        setCurrentScreen('Chats');
                    }
                } catch(error) {
                    //console.error(error);
                    ErrorAlert(error.message, error);  // Network error
                    setCurrentScreen('Retry');
                }        
            } catch(error) {
                // any exception including data not found goes to catch()
                switch (error.name) {
                  case 'NotFoundError':
                    setCurrentScreen('Register');
                    break;
                  case 'ExpiredError':
                    setCurrentScreen('Register');
                    break;
                  default:
                    ErrorAlert(error.message, error);  // Storage error
                    setCurrentScreen('Register');
                }
            }
        }                                 
    }


    ComponentRefresh();


    if         (currentScreen === 'Retry') {
        return (<SafeAreaView style={styles.container}><View style={styles.safeview}><View style={styles.centercenterflex1}><Button title='Reload' onPress={() => setCurrentScreen('Init')} /></View></View></SafeAreaView>);
    } else if  (currentScreen === 'Register') {
        return (<SafeAreaView style={styles.container}><View style={styles.safeview}><RegisterComponent setCurrentScreenInCurrentComponent={setCurrentScreen} setAccountDataInCurrentComponent={setAccountData} /></View></SafeAreaView>);
    } else if (currentScreen === 'Chats') {
        return (<SafeAreaView style={styles.container}><View style={styles.safeview}><ChatsComponent setCurrentScreenInCurrentComponent={setCurrentScreen} setOpenedPrivateChatInCurrentComponent={setOpenedPrivateChat} AccountData={AccountData} /></View></SafeAreaView>);
    } else if (currentScreen === 'Settings') {
        return (<SafeAreaView style={styles.container}><View style={styles.safeview}><SettingsComponent setCurrentScreenInCurrentComponent={setCurrentScreen} AccountData={AccountData} /></View></SafeAreaView>);
    } else if (currentScreen === 'PrivateChat') {
        return (<SafeAreaView style={styles.container}><View style={styles.safeview}><PrivateChatComponent setCurrentScreenInCurrentComponent={setCurrentScreen} remoteUsername={openedPrivateChat} AccountData={AccountData} /></View></SafeAreaView>);
    } else if (currentScreen === 'WaitReload') {
        return (<SafeAreaView style={styles.container}><View style={styles.safeview}><View style={styles.centercenterflex1}><Text>Reloading, please wait...</Text></View></View></SafeAreaView>);
    } else {  // This is shown while the app is loaded for the first time
        return (<SafeAreaView style={styles.container}><View style={styles.safeview}><View style={styles.centercenterflex1}><Text> </Text></View></View></SafeAreaView>);
    }


}



registerRootComponent(App);















