import { StyleSheet, SafeAreaView, StatusBar, Platform, Button, Text, TextInput, View, Alert, Dimensions,  PixelRatio, TouchableWithoutFeedback } from 'react-native';
//import { StatusBar } from 'expo-status-bar';
import React, {useState} from 'react';


const fontScale = PixelRatio.getFontScale();
const getFontSize = size => size / fontScale;



export const styles = StyleSheet.create({

  minuscule: {
    fontSize: getFontSize(8),  
  },

  tiny: {
    fontSize: getFontSize(10),  
  },

  small: {
    fontSize: getFontSize(12),  
  },

  medium: {
    fontSize: getFontSize(14),  
  },

  big: {
    fontSize: getFontSize(16),  
  },

  large: {
    fontSize: getFontSize(18),  
  },

  enormous: {
    fontSize: getFontSize(20),  
  },

  usernamestyle: {
    fontSize: getFontSize(20),  
    fontWeight: 'bold'
  },

  container: { // fills up space, used in system components
    flex:1,
  },
  container1: { // fills up space
    flex:1,
    backgroundColor: '#fff',
    alignSelf: "stretch",
  }, 
  centercenterflex1: { // fills up space, all centered
    flex:1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
  },
  centerleftflex1: { // fills up space, vertical alignment middle, horizontal alignment left
    flex:1,
    backgroundColor: '#fff',
    flexDirection:'row', 
    justifyContent:'flex-start', 
    alignItems: 'center',
    alignSelf: "stretch",
  },
  leftcenter: {  // aligns center, does not fill
    flexDirection:'row', 
    justifyContent:'center', 
    alignItems: 'center', 
    backgroundColor: '#fff', 
    alignSelf: "center",
  },  
  leftleft: {  // aligns left, does not fill
    flexDirection:'row', 
    justifyContent:'flex-start', 
    alignItems: 'flex-start', 
    backgroundColor: '#fff', 
    alignSelf: "stretch",
  },
  textfield: {
    backgroundColor: '#aaa',
    width: 160,
    fontSize: getFontSize(16),    
  },
  space: {
    backgroundColor: '#fff',
    flexDirection:'row', 
    justifyContent:'flex-start', 
    alignItems: 'flex-start', 
    alignSelf: "stretch",
    fontSize: getFontSize(6),    
  }, 
  tabselector: {
    flexDirection:'row', 
    justifyContent:'center', 
    alignItems: 'flex-start', 
    backgroundColor: '#aaa', 
    alignSelf: "stretch",
    fontSize: getFontSize(22),    
  }, 
  headertitle: { 
    justifyContent:'flex-start', 
    alignItems: 'center', 
    backgroundColor: '#aaa', 
    justifyContent: 'center',
    alignSelf: "stretch",
    fontSize: getFontSize(19),    
  },
  headertitlewithback: {
    flexDirection:'row',   
    justifyContent:'flex-start', 
    alignItems: 'center', 
    backgroundColor: '#aaa', 
    justifyContent: 'center',
    alignSelf: "stretch",
    fontSize: getFontSize(19),    
  },
  headertitleleftleft: {
    flexDirection:'row', 
    justifyContent:'flex-start', 
    alignItems: 'flex-start', 
    backgroundColor: '#aaa', 
    alignSelf: "stretch",
  },
  headertitlecentercenterflex1: { 
    flex:1,
    backgroundColor: '#aaa',
    alignItems: 'center',
    justifyContent: 'center',
  },  
  headertitleleftcenter: {  
    flexDirection:'row', 
    justifyContent:'center', 
    alignItems: 'center', 
    backgroundColor: '#aaa', 
    alignSelf: "center",
  }, 
  bglightblue: { 
    backgroundColor: '#eef', 
  },
  safeview: {
    flex: 1,
    paddingTop: Platform.OS === "android" ? StatusBar.currentHeight : 0,
    fontSize: getFontSize(12),    
  },
  default: {
  }
});



export const RuleComponent = () => {
    return(
        <View
          style={{
            borderBottomColor: 'black',
            borderBottomWidth: StyleSheet.hairlineWidth,
          }}
        />
    );
}



export const ChatSelectorComponent = props => {
    return(
    <TouchableWithoutFeedback onPress={() => 
        {
          props.setCurrentScreenInChatSelectorComponent('PrivateChat');
          props.setOpenedPrivateChatInChatSelectorComponent(props.username);
        }      
      }>
        <View {...props} style={styles.bglightblue}>
            <RuleComponent />
            <Text style={styles.minuscule}></Text>
            <Text style={styles.large}>    {props.username}</Text>
            <Text style={styles.minuscule}></Text>
        </View>
    </TouchableWithoutFeedback>
    );
}


