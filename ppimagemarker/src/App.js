//See: https://github.com/charpeni/react-native-url-polyfill#readme
import 'react-native-url-polyfill/auto';

import { StatusBar } from 'expo-status-bar';
import { StyleSheet, Text, View, SafeAreaView, AppRegistry } from 'react-native';
import React, {useState, useCallback, useEffect, useRef} from 'react';

import * as Linking from "expo-linking";

//import { Mutex, Semaphore, withTimeout, tryAcquire, E_ALREADY_LOCKED, E_TIMEOUT } from 'async-mutex';

import { registerRootComponent } from 'expo';

import { name as appName } from "../app.json";

import { NavigationContainer } from "@react-navigation/native";
import { createNativeStackNavigator } from "@react-navigation/native-stack";

import { useNavigation } from '@react-navigation/native';



import { TabsComponent } from './visuals/Tabs.jsx';
import { PPInitComponent } from "./visuals/PPInit.jsx";
import { PPSettingsComponent } from "./visuals/PPSettings.jsx";
import { PPTaggingComponent } from "./visuals/PPTagging.jsx";
import { PPNotFoundComponent } from "./visuals/PPNotFound.jsx";

import { ErrorAlert, InitialisationActions, LogMe, UpdateLogMeUsername } from './myGeneralLibrary.jsx';
import storage from './storage/storageApi.js';
import { styles, LoadingComponent } from './visuals/myVisualsLibrary.jsx';

import 'react-native-url-polyfill/auto';  // https://www.davidangulo.xyz/posts/use-url-class-in-react-native/



const prefix = Linking.createURL("/");

/** A: "B"
 *  A is the reference to the screen; must match with the name property of Stack.Screen
 * "B" is the name of the deep link page, which will have to be used by the external app
*/
const config = {
  screens: {
    Init: "pptagging",
    PPNotFound: '*',
  },
};

const linking = {
  prefixes: [prefix],
  config,
};

const Stack = createNativeStackNavigator();




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
          await InitialisationActions();
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
      <View style={styles.safeview}>
        <NavigationContainer linking={linking} fallback={<LoadingComponent />}>
          <StatusBar animated={false} backgroundColor="transparent" />
          <Stack.Navigator initialRouteName="Init" screenOptions={{ animation: 'none' }}>
            <Stack.Screen options={{headerShown: false}} name="Init" component={PPInitComponent} />
            <Stack.Screen options={{headerShown: false}} name="PPSettings" component={PPSettingsComponent} />
            <Stack.Screen options={{headerShown: false}} name="PPTagging" component={PPTaggingComponent} />
            <Stack.Screen options={{headerShown: false}} name="PPNotFound" component={PPNotFoundComponent} />
          </Stack.Navigator>
        </NavigationContainer>
      </View>
    </SafeAreaView>
  );
  
}


registerRootComponent(App);


