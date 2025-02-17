import { StatusBar } from 'expo-status-bar';
import { StyleSheet, Text, View, SafeAreaView, AppRegistry, Button } from 'react-native';
import React, {useState, useCallback, useEffect, useRef} from 'react';

import * as Linking from "expo-linking";
import * as Integrity from 'expo-app-integrity';

import { name as appName } from "../../app.json";

import { NavigationContainer } from "@react-navigation/native";
import { createNativeStackNavigator } from "@react-navigation/native-stack";


import { ErrorAlert, InitialisationActions, LogMe, UpdateLogMeUsername } from '../myGeneralLibrary.jsx';
import * as storage from '../storage/storageApi.js';
import { styles, LoadingComponent } from './myVisualsLibrary.jsx';



export const PPInitComponent = ({ route, navigation }) => {


    const [initStatus, setInitStatus] = useState({ key: 'init' });
    // This is the screen that will be loaded at startup:
    const [navigatorInitialScreen, setnavigatorInitialScreen] = useState({key: 'PPEnrollment'});  // Changing this state DOES NOT trigger a component refresh
    const [accountData, setAccountData] = useState({key: {}});



    useEffect( () => {  // This is executed when the component is reloaded
        async function didMount() { // Do not change the name of this function
            // Do stuff
            LogMe(1, 'useEffect of PPInit invocation');      

            try {
                await InitialisationActions();   
            } catch(error) {
                ErrorAlert('Error when initializing app.', error);  // Some error
            }

            try {
                const storagenewdata = {
                    options: {},        
                    key: 'accountData',
                };
                let retStorage = await storage.load(storagenewdata);
                LogMe(1,'Loaded from storage: '+JSON.stringify(retStorage));
                
                if (retStorage === null) {
                    LogMe(2, 'Setting defaults for in-memory accountData');
                    // Default volatile startup values
                    accountData.key = {
                      'username': 'ppuser',  
                      'PPIcookie': '',  
                      'PPEcookie': '',  
                      'enrollmentAttempted': false,  
                      'enrollmentCompleted': false,  
                      'iosKeyName': '',
                    };    
                } else {
                    // Previously stored values
                    accountData.key = { ...retStorage };
                    UpdateLogMeUsername(retStorage.username);
                }      
            } catch(error) {
                ErrorAlert(error.message, error);  // Storage error
            }

            navigation.navigate(
                navigatorInitialScreen.key, {
                    AccountData: accountData.key,
                }
            );

    
        }
        didMount();  // If we want useEffect to be asynchronous, we have to define didMount as async and call it right after
        return async function didUnmount() { // Do not change the name of this function
          // Cleanup tasks
          LogMe(1, 'useEffect of PPInit cleanup');
        };
    }, []);  // App.js does not have props


    async function ComponentRefresh() {  // Invoked every time this screen is loaded
        LogMe(1, 'Refreshing PPInit Component');
        if (initStatus.key === 'init') {
            LogMe(1, 'Initialising PPInit Component');
            initStatus.key = 'updated'; //update without rendering
            //initStatus({ key:'updated'}); //update with rendering
            // This will reach only on the first time the scren is loaded
        }
    }

    ComponentRefresh();


    return (
        <LoadingComponent />
    );
};



