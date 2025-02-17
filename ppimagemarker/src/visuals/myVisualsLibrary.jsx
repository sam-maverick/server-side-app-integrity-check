import { StyleSheet, SafeAreaView, StatusBar, Platform, Button, Text, TextInput, View, Alert, Dimensions,  PixelRatio, TouchableWithoutFeedback } from 'react-native';
import React, {useState} from 'react';


const fontScale = PixelRatio.getFontScale();
const getFontSize = size => size / fontScale;

var winwidth = Dimensions.get('window').width;

export const styles = StyleSheet.create({

  imagewrp: {
    flex: 1,
    width: winwidth * 0.75,  //its same to '75%' of device width
    aspectRatio: 1, // <-- this
    resizeMode: 'contain', //optional
  },
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
  explanation: {
    fontSize: getFontSize(12),  
    color: '#777777',
  },
  explanationalert: {
    fontSize: getFontSize(12),  
    color: 'red',
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
  leftleftlist: {  // aligns left, does not fill
    flexDirection:'column', 
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


export const LoadingComponent = () => {
  return(
    <View style={styles.centercenterflex1}><Text>Loading...</Text></View> 
  );
}

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




