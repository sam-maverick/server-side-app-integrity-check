//import { StatusBar } from 'expo-status-bar';
import React, {useState} from 'react';
import { StyleSheet, Button, Text, TextInput, View } from 'react-native';

import { styles } from './myVisualsLibrary.jsx';
import { ErrorAlert, LogMe } from '../myGeneralLibrary.jsx';


export const TabsComponent = props => {

    async function ComponentRefresh() {    
        LogMe(1, 'Refreshing Tabs Component');
    }


    ComponentRefresh();
    

    return (
            
            <View style={styles.headertitle}>
            {/*
                <View style={styles.space}>
                    <Text style={styles.medium}></Text>
                </View>
            */}
                <View style={styles.tabselector}>
                    <Button {... (props.activeTab!='Chats') ? {color:'gray'} : {}} title='Chats' onPress={() => props.setCurrentScreenInTabsComponent('Chats')} />
                    <Button {... (props.activeTab!='Settings') ? {color:'gray'} : {}} title='Settings' onPress={() => props.setCurrentScreenInTabsComponent('Settings')} />
                </View>
            </View>
            
    );
};



