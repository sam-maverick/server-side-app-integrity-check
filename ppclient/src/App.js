//See: https://github.com/charpeni/react-native-url-polyfill#readme
import 'react-native-url-polyfill/auto';

//https://solana.stackexchange.com/questions/6242/error-while-sending-transaction-with-solanaweb3-referenceerror-property-buff
global.Buffer = require('buffer').Buffer;

import { StatusBar } from 'expo-status-bar';
import { StyleSheet, Text, View, SafeAreaView, AppRegistry } from 'react-native';
import React, {useState, useCallback, useEffect, useRef} from 'react';

import { MenuProvider } from 'react-native-popup-menu';

import * as Linking from "expo-linking";
import * as Integrity from 'expo-app-integrity';

//import { Mutex, Semaphore, withTimeout, tryAcquire, E_ALREADY_LOCKED, E_TIMEOUT } from 'async-mutex';

import { registerRootComponent } from 'expo';

import { name as appName } from "../app.json";

import { NavigationContainer } from "@react-navigation/native";
import { createNativeStackNavigator } from "@react-navigation/native-stack";

import { useNavigation } from '@react-navigation/native';

import { PARAM_PP__CRYPTO } from './parameters.js';

import { TabsComponent } from './visuals/Tabs.jsx';
import { PPInitComponent } from "./visuals/PPInit.jsx";
import { PPReloadComponent } from "./visuals/PPReload.jsx";
import { PPWrapOpsComponent, PPWrapHandleURL } from "./visuals/PPWrapOps.jsx";
import { PPSettingsComponent } from "./visuals/PPSettings.jsx";
import { PPIntegrityComponent } from "./visuals/PPIntegrity.jsx";
import { PPEnrollmentComponent } from "./visuals/PPEnrollment.jsx";
import { PPNotFoundComponent } from "./visuals/PPNotFound.jsx";

import { ErrorAlert, InitialisationActions, LogMe, UpdateLogMeUsername, AsyncAlert } from './myGeneralLibrary.jsx';
import { storage } from './storage/storageApi.js';
import { styles, LoadingComponent } from './visuals/myVisualsLibrary.jsx';

import 'react-native-url-polyfill/auto';  // https://www.davidangulo.xyz/posts/use-url-class-in-react-native/



const prefix = Linking.createURL("/");

/** A: "B"
 *  A is the reference to the screen; must match with the name property of Stack.Screen
 * "B" is the name of the deep link page, which will have to be used by the external app
*/
const config = {
  screens: {
    PPWrapOps: "wrapoperation",
    PPNotFound: '*',
  },
};

const linking = {
  prefixes: [prefix],
  config,
};

const Stack = createNativeStackNavigator();

/*
// Not necessary, as all URL events will lead to navigation to the PPWrapOpsComponent 
// and will trigger a RefreshComponent with all the URL params in the props
LogMe(1, 'Linking.addEventListener() subscription');
Linking.addEventListener('url', async ({ url }) => {
    LogMe(1,'Link event triggered from addEventListener()');
    const navigation = useNavigation();
    navigation.navigate(
        'PPWrapOps', {}
    );  // Any params here have no effect as it is in App.js
});   
*/


export default function App() {

  const [currentScreen, setCurrentScreen] = useState('Init');  // DUMMY.   NOT ANY MORE With Navigation: Changing this state triggers a component refresh
  //const [navigatorCurrentScreen, setNavigatorCurrentScreen] = useState({key: 'Init'});  // Changing this state DOES NOT trigger a component refresh

    /*
    NOTE:
    These are some particularities of useEffect in App.js (the app's entry point), compared to other components:
    - There is no props.
    - It is called just once, when the app is launched.
    */
    useEffect( () => {  // This is executed when the app is launched
      async function didMount() { // Do not change the name of this function
          // Do stuff
          LogMe(1, 'useEffect of PPApp invocation');         
        }
      didMount();  // If we want useEffect to be asynchronous, we have to define didMount as async and call it right after
      return async function didUnmount() { // Do not change the name of this function
        // Cleanup tasks
        LogMe(1, 'useEffect of PPApp cleanup');
      };
  }, []);  // App.js does not have props




  // This is executed whenever the currentScreen is changed
  async function ComponentRefresh() {    
      LogMe(1, 'Refreshing PPApp Component');

      if (currentScreen === 'Init') {   
      
          LogMe(1, 'Initialising PPApp Component');

          setCurrentScreen('No-Init');
  
      }                                 
  }


  ComponentRefresh();


  return (
    <SafeAreaView style={styles.container}>
      <MenuProvider>
        <View style={styles.safeview}>
          <NavigationContainer linking={linking} fallback={<LoadingComponent />}>
            <StatusBar animated={false} backgroundColor="transparent" />
            <Stack.Navigator initialRouteName="Init" screenOptions={{ animation: 'none' }}>
              <Stack.Screen options={{headerShown: false}} name="Init" component={PPInitComponent} />
              <Stack.Screen options={{headerShown: false}} name="PPReload" component={PPReloadComponent} />
              <Stack.Screen options={{headerShown: false}} name="PPSettings" component={PPSettingsComponent} />
              <Stack.Screen options={{headerShown: false}} name="PPIntegrity" component={PPIntegrityComponent} />
              <Stack.Screen options={{headerShown: false}} name="PPEnrollment" component={PPEnrollmentComponent} />
              <Stack.Screen options={{headerShown: false}} name="PPWrapOps" component={PPWrapOpsComponent} />
              <Stack.Screen options={{headerShown: false}} name="PPNotFound" component={PPNotFoundComponent} />
            </Stack.Navigator>
          </NavigationContainer>
        </View>
      </MenuProvider>
    </SafeAreaView>
  );
  
}


registerRootComponent(App);


