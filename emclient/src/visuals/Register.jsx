//import { StatusBar } from 'expo-status-bar';
import React, {useState, useCallback, useEffect, useRef} from 'react';
import { StyleSheet, Button, Text, TextInput, View, Alert } from 'react-native';

//import Storage from 'react-native-storage';
//import AsyncStorage from '@react-native-async-storage/async-storage';


import { styles } from './myVisualsLibrary.jsx';
import { ErrorAlert, LogMe, UpdateLogMeUsername } from '../myGeneralLibrary.jsx';
import { TabsComponent } from './Tabs.jsx';

import { ApiCreateAccount } from '../network/networkApi.js';

import storage from '../storage/storageApi.js';
import { PARAM_SERVER_API_URL } from '../parameters.js';




export const RegisterComponent = props => {

    const [newAccount, setNewAccount] = useState('');
    const [initStatus, setInitStatus] = useState({ key: 'init' });

    useEffect( () => {  // This is executed when the app is launched
        async function didMount() { // Do not change the name of this function
            // Do stuff
            LogMe(1, 'useEffect of Register invocation');           
        }
        didMount();  // If we want useEffect to be asynchronous, we have to define didMount as async and call it right after
        return async function didUnmount() { // Do not change the name of this function
          // Cleanup tasks
          LogMe(1, 'useEffect of Register cleanup');
        };
    }, []);  // App.js does not have props


    async function ComponentRefresh() {  // Invoked every time this screen is loaded
        LogMe(1, 'Refreshing Register Component');
        if (initStatus.key === 'init') {
            LogMe(1, 'Initialising Register Component');
            initStatus.key = 'updated'; //update without rendering
            //initStatus({ key:'updated'}); //update with rendering
            // This will reach only on the first time the scren is loaded
        }
    }


    function setCurrentScreenInMainComponent(newState) {
        props.setCurrentScreenInCurrentComponent(newState);
    }
    function setAccountDataInMainComponent(newData) {
        props.setAccountDataInCurrentComponent(newData);
    }
    
    async function CreateAccount(username) {
        try {
            let resApi = await ApiCreateAccount(username);
            if (!resApi.isSuccessful) {
                ErrorAlert(resApi.resultMessage);  // Server-side error
            } else {
                try {
                    await storage.save({
                        key: 'accountData', // Note: Do not use underscore("_") in key!
                        data: {
                            'username': username,
                            'cookie': resApi.user.cookie,
                        },
                    });
                } catch(error) { 
                    ErrorAlert(error.message, error);  // Storage error
                }           
                setAccountDataInMainComponent({'username': username, 'cookie' : resApi.user.cookie});
                UpdateLogMeUsername(username);
                setCurrentScreenInMainComponent('Chats');
            }
        } catch(error) {
            //console.error(error);
            ErrorAlert(error.message + '(' + PARAM_SERVER_API_URL + ')', error);  // Network error
        }
    }    


    ComponentRefresh();


    return (
        <View style={styles.centercenterflex1}>
            <View style={styles.headertitle}>
                <Text style={styles.large}>Registration</Text>
            </View>
            <View style={styles.centercenterflex1}>
                <Text style={styles.medium}> </Text>
                <Text style={styles.medium}>Choose a username:</Text>
                <TextInput
                    style={styles.textfield}
                    onChangeText={newText => setNewAccount(newText)}
                    defaultValue={newAccount}
                />
                <Text style={styles.medium}> </Text>
                <Text style={styles.medium}> </Text>
                <Button title='Submit' onPress={() => CreateAccount(newAccount)} />
            </View>
        </View>
    );
};



