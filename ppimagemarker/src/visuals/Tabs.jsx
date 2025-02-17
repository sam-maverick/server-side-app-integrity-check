//import { StatusBar } from 'expo-status-bar';
import React, {useState} from 'react';
import { StyleSheet, Button, Text, TextInput, View } from 'react-native';

import { styles } from './myVisualsLibrary.jsx';
import { ErrorAlert, LogMe } from '../myGeneralLibrary.jsx';

import { useNavigation } from '@react-navigation/native';



export const TabsComponent = props => {

    const navigation = useNavigation();


    async function ComponentRefresh() {    
        LogMe(1, 'Refreshing PPTabs Component');
    }


    ComponentRefresh();


    return (
            
            <View style={styles.headertitle}>

                <View style={styles.tabselector}>
                    <Button {... (props.activeTab!='PPSettings') ? {color:'gray'} : {}} title='Settings' onPress={() => navigation.navigate('PPSettings', props.props.propsState)} />
                    <Button {... (props.activeTab!='PPTagging') ? {color:'gray'} : {}} title='Tagging' onPress={() => navigation.navigate('PPTagging', props.props.propsState)} />
                </View>
            </View>
            
    );
};



