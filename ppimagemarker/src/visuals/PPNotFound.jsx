import React, {useState, useCallback, useEffect, useRef} from 'react';
import { StyleSheet, Button, Text, TextInput, View, Alert, ScrollView, Platform } from 'react-native';

import * as Linking from 'expo-linking';

import { styles } from './myVisualsLibrary.jsx';
import { ErrorAlert, LogMe, UpdateLogMeUsername } from '../myGeneralLibrary.jsx';

//import storage from '../storage/storageApi.js';



export const PPNotFoundComponent = ({ route, navigation }) => {

    const [initStatus, setInitStatus] = useState({ key: 'init' });
    const [propsState, setPropsState] = useState(route.params);
    const [initialUrl, setInitialUrl] = useState('');

    useEffect( () => {  // This is executed when the component is reloaded
        async function didMount() { // Do not change the name of this function
            // Do stuff
            LogMe(1, 'useEffect of PPNotFound invocation');    
            let requestedUrl = await Linking.getInitialURL();                
            setInitialUrl(requestedUrl);
        }
        didMount();  // If we want useEffect to be asynchronous, we have to define didMount as async and call it right after
        return async function didUnmount() { // Do not change the name of this function
          // Cleanup tasks
          LogMe(1, 'useEffect of PPNotFound cleanup');
        };
    }, []);  // App.js does not have props


    async function ComponentRefresh() {  // Invoked every time this screen is loaded
        LogMe(1, 'Refreshing PPNotFound Component');
        if (initStatus.key === 'init') {
            LogMe(1, 'Initialising PPNotFound Component');
            initStatus.key = 'updated'; //update without rendering
            //initStatus({ key:'updated'}); //update with rendering
            // This will reach only on the first time the scren is loaded
        }
    }


    ComponentRefresh();

    return (
        <View style={styles.centercenterflex1}>
            <View style={styles.headertitle}>
                <Text style={styles.large}>Not Found</Text>
            </View>
            <View style={styles.centerleftflex1}>
                <View style={styles.leftleft}>
                    <Text>       </Text>{/* Left margin */}
                </View>
                <View style={styles.centerleftflex1}>
                    <ScrollView style={styles.scrollView}>{/* ScrollView already expands, so we set their children not to expand, otherwise the buttons expand */}

                    <View style={styles.leftleft}>
                        <Text style={styles.medium}>Ooops.</Text>
                    </View>
                    <View style={styles.leftleft}>
                        <Text style={styles.medium}> </Text>
                    </View>
                    <View style={styles.leftleft}>
                        <Text style={styles.medium}>There has been an error. Some other app requested a deep link that does not exist within our app. The link is:</Text>
                    </View>
                    <View style={styles.leftleft}>
                        <Text style={styles.medium}> </Text>
                    </View>
                    <View style={styles.leftleft}>
                        <Text style={styles.medium}>{ initialUrl }</Text>
                    </View>

                    </ScrollView>
                </View>
                <View style={styles.leftleft}>
                    <Text>       </Text>{/* Right margin */}
                </View>
            </View>
        </View>
    );
};



