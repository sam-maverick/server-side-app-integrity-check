//import { StatusBar } from 'expo-status-bar';
import React, {useState, useCallback, useEffect, useRef} from 'react';
import { StyleSheet, Button, Text, TextInput, View, ScrollView } from 'react-native';

//import Storage from 'react-native-storage';
//import AsyncStorage from '@react-native-async-storage/async-storage';



import storage from '../storage/storageApi.js';

import { TabsComponent } from './Tabs.jsx';
import { styles, RuleComponent, normalize, ChatSelectorComponent } from './myVisualsLibrary.jsx';
import { ErrorAlert, LogMe } from '../myGeneralLibrary.jsx';
import { ApiGetAccountsList } from '../network/networkApi.js';



export const ChatsComponent = props => {

  const [initStatus, setInitStatus] = useState({ key: 'init' });
  const [listOfAccounts, setListOfAccounts] = useState([]);
  const [numOfAccounts, setNumOfAccounts] = useState(-1);
  

    function setCurrentScreenInMainComponent(newState) {
        props.setCurrentScreenInCurrentComponent(newState);
    }

    function setOpenedPrivateChatInMainComponent(newState) {
        props.setOpenedPrivateChatInCurrentComponent(newState);
    }

    useEffect( () => {  // Invoked every time this Screen is loaded
        async function didMount() { // Do not change the name of this function
            // Do stuff
            LogMe(1, 'useEffect of Chats invoked');
            await DoInternalRefresh();
        }
        didMount();  // If we want useEffect to be asynchronous, we have to define didMount as async and call it right after
        return async function didUnmount() { // Do not change the name of this function
          // Cleanup tasks
          LogMe(1, 'useEffect of Chats cleanup');
        };
    }, [props]);  // Put [] if the useEffect code does not need to access props or parameters, or set to [props.state1] or to [props] otherwise


    async function ComponentRefresh() {  // Invoked every time this screen is loaded
        LogMe(1, 'Refreshing Chats Component');
        if (initStatus.key === 'init') {
            LogMe(1, 'Initialising Chats Component');
            initStatus.key = 'updated'; //update without rendering
            //initStatus({ key:'updated'}); //update with rendering
            // This will reach only on the first time the scren is loaded
        }
    }
   
    async function DoInternalRefresh() {
        LogMe(1, 'DoInternalRefresh()');
        //send request
        try {
            let apires = await ApiGetAccountsList(props.AccountData.cookie);
            if (!apires.isSuccessful) {
                ErrorAlert(apires.resultMessage);  // Server-side application error
                setCurrentScreenInMainComponent('Init');                    
            } else {
                setListOfAccounts(apires.listOfAllUsernames);
                setNumOfAccounts(apires.listOfAllUsernames.length);
            }
        }
        catch(error) {
            //console.error(error);
            ErrorAlert(error.message, error);  // Network error
        }
    }

    function showAccountsList(myname) {
            const arr = [];
            Object.keys(listOfAccounts).forEach(function(key) {
                if (myname != listOfAccounts[key].username) {
                  arr.push(<ChatSelectorComponent key={listOfAccounts[key].username} username={listOfAccounts[key].username} setCurrentScreenInChatSelectorComponent={setCurrentScreenInMainComponent} setOpenedPrivateChatInChatSelectorComponent={setOpenedPrivateChatInMainComponent} />);
                }
            }); 
            if (arr == []) {
                // Not initialised yet
                return (<Text style={styles.medium}> </Text>);  // Not initialized yet
            } else {
                // Initialised
                return arr;            
            }  
    }

    // Call init
    ComponentRefresh();
           
    return (
        <View style={styles.centercenterflex1}>
            <View style={styles.headertitle}>
                <Text style={styles.large}>Your private chats</Text>
            </View>
            <Text> </Text>
            <Button title='Refresh' onPress={() => DoInternalRefresh()} />
            <Text> </Text>
            <View style={styles.centerleftflex1}>
                <ScrollView style={styles.scrollView}>
              
                {  (numOfAccounts==1) ? <Text>        There are no other users to chat with.</Text> : showAccountsList(props.AccountData.username) }              

                {  (numOfAccounts>1) ? <RuleComponent /> : <Text></Text> }              
              
                { /* <Text style={styles.minuscule}></Text> */ }
                </ScrollView>
            </View>
            <TabsComponent setCurrentScreenInTabsComponent={setCurrentScreenInMainComponent} activeTab="Chats" />
        </View>
    );
};



