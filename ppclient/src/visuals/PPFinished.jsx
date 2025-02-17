//import { StatusBar } from 'expo-status-bar';
import React, {useState, useCallback, useEffect, useRef} from 'react';
import { StyleSheet, Button, Text, TextInput, View, Alert, ScrollView, Platform } from 'react-native';
import * as Device from 'expo-device';
import RNRestart from 'react-native-restart';  // Use only in PROD
import { DevSettings} from 'react-native';  // Use only in DEV

import { TabsComponent } from './Tabs.jsx';

import { styles } from './myVisualsLibrary.jsx';
import { ErrorAlert, LogMe, UpdateLogMeUsername } from '../myGeneralLibrary.jsx';

import storage from '../storage/storageApi.js';



export const PPFinishedComponent = (props) => {

    const [initStatus, setInitStatus] = useState({ key: 'init' });
    const [propsState, setPropsState] = useState(props.route.params);

    // Internal state, only initialized when 
    const [internalSyncState, setInternalState] = useState({ attempted: false, completed: false });
    const [internalDummyState, setInternalDummyState] = useState();  // Used to force refresh


    useEffect( () => {  // This is executed when the component is reloaded
        async function didMount() { // Do not change the name of this function

            // Do stuff
            LogMe(1, 'useEffect of PPFinished invocation');  

            // See: https://stackoverflow.com/questions/38558200/react-setstate-not-updating-immediately
            // Warning: Despite not being formally an asynchronous function, setState is performed asynchronously
            // except if we access the state directly without its 'set' function and the value is a {} object:

        }

        didMount();  // If we want useEffect to be asynchronous, we have to define didMount as async and call it right after
        return async function didUnmount() { // Do not change the name of this function
          // Cleanup tasks
          LogMe(1, 'useEffect of PPFinished cleanup');
        };
    }, []);  // App.js does not have props


    async function ComponentRefresh() {  // Invoked every time this screen is loaded
        LogMe(1, 'Refreshing PPFinished Component');
        if (initStatus.key === 'init') {
            LogMe(1, 'Initialising PPFinished Component');
            initStatus.key = 'updated'; //update without rendering
            //initStatus({ key:'updated'}); //update with rendering
            // This will reach only on the first time the scren is loaded
        }
    }
    

    // Initialisation
    ComponentRefresh();
    
    //We also load PPWrapComponent in the background to let it subscribe URL events when the app is already opened
    return (
        <View style={styles.centercenterflex1}>

            <View style={styles.headertitle}>
                <Text style={styles.large}></Text>
            </View>
            <View style={styles.centerleftflex1}>
                <View style={styles.leftleft}>
                    <Text>       </Text>{/* Left margin */}
                </View>
                <View style={styles.centerleftflex1}>
                    <Text></Text>
                </View>
                <View style={styles.leftleft}>
                    <Text>       </Text>{/* Right margin */}
                </View>
            </View>
            <TabsComponent activeTab="None" props={{propsState}} />
        </View>
    );
};
