//import { StatusBar } from 'expo-status-bar';
import React, {useState, useCallback, useEffect, useRef} from 'react';
import { StyleSheet, Button, Text, TextInput, View, Alert, ScrollView, Platform } from 'react-native';

//import { useNavigation } from '@react-navigation/native';

import { TabsComponent } from './Tabs.jsx';

import { styles } from './myVisualsLibrary.jsx';
import { ErrorAlert, LogMe, UpdateLogMeUsername } from '../myGeneralLibrary.jsx';

import storage from '../storage/storageApi.js';

import { 
    PARAM_PRIVATE_PICTURES_ALBUM_NAME,
    PARAM_PRIVATE_PICTURES_TMP_DIRNAME,
    PARAM_WELCOME_MESSAGE,
 } from '../parameters.js';







export const PPSettingsComponent = ({ route, navigation }) => {

    const [initStatus, setInitStatus] = useState({ key: 'init' });
    const [networkStatus, setNetworkStatus] = useState('(press button)');
    const [propsState, setPropsState] = useState(route.params);

    useEffect( () => {  // This is executed when the component is reloaded
        async function didMount() { // Do not change the name of this function
            // Do stuff
            LogMe(1, 'useEffect of PPSettings invocation');           
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
    


    async function SaveUsername(newusername) {
        let cloneOfProps = {AccountData: propsState.AccountData};  // Force pass-by-value
        cloneOfProps.AccountData.username = newusername;

        try {
            await storage.save({
                key: 'accountData', // Note: Do not use underscore("_") in key!
                data: cloneOfProps.AccountData,
            });
        } catch(error) { 
            ErrorAlert(error.message, error);  // Storage error
        }

        setPropsState(cloneOfProps);
        
        UpdateLogMeUsername(newusername);
    }    



    // Initialisation
    ComponentRefresh();
    
    
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

                    <View style={styles.leftleft}>
                            <Text>ABOUT THIS APP:</Text>
                        </View>

                        <Text />

                        <View style={styles.leftleft}>
                            <Text>{PARAM_WELCOME_MESSAGE}</Text>
                        </View>

                        <Text />

                        <View style={styles.leftleft}>
                            <Text style={{fontWeight: "bold"}}>Username is: </Text>
                            <TextInput
                                style={styles.textfield}
                                onChangeText={newText => SaveUsername(newText)}
                                defaultValue={propsState.AccountData.username}
                            />
                        </View>
                        <View style={styles.leftleft}>
                            <Text>Used only for debugging.</Text>
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
