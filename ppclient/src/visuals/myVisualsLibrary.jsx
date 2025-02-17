import { StyleSheet, SafeAreaView, StatusBar, Platform, Button, Text, TextInput, View, Alert, Dimensions,  PixelRatio, TouchableWithoutFeedback } from 'react-native';
import React, {useState} from 'react';


const fontScale = PixelRatio.getFontScale();
const getFontSize = size => size / fontScale;

var winwidth = Dimensions.get('window').width;

export const styles = StyleSheet.create({

  imagewrpfull: {
    flex: 1,
    width: '100%',
    height: '100%', 
    resizeMode: 'contain', //optional
  },
  imagewrp: {
    flex: 1,
    width: winwidth * 0.75,  //it is same as '75% of device width'
    aspectRatio: 1, // <-- this
    resizeMode: 'contain', //optional
  },
  imagewrpcentered: {
    flex: 1,
    width: winwidth * 0.75,  //it is same as '75% of device width'
    aspectRatio: 1, // <-- this
    resizeMode: 'contain', //optional
    flexDirection:'row', 
    justifyContent:'center', 
    alignItems: 'center',
    alignSelf: "stretch",
  },
  minuscule: {
    fontSize: getFontSize(8),  
  },

  tiny: {
    fontSize: getFontSize(10),  
  },

  link: {
    color: '#0000FF',
  },

  explanation: {
    fontSize: getFontSize(12),  
    color: '#777777',
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
  centerleftflex1black: { // fills up space, vertical alignment middle, horizontal alignment left
    flex:1,
    backgroundColor: '#000',
    flexDirection:'row', 
    justifyContent:'flex-start', 
    alignItems: 'center',
    alignSelf: "stretch",
  },
  centerleftflex1blackcol: { // fills up space, vertical alignment middle, horizontal alignment left
    flex:1,
    backgroundColor: '#000',
    flexDirection:'column', 
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
  leftleftline: {  // aligns left, does not fill
    flexDirection:'row', 
    justifyContent:'flex-start', 
    alignItems: 'flex-start', 
    backgroundColor: 'green', 
    alignSelf: "stretch",
  },
  leftleftlinebg: {  // aligns left, does not fill
    flexDirection:'row', 
    justifyContent:'flex-start', 
    alignItems: 'flex-start', 
    backgroundColor: 'black', 
    alignSelf: "stretch",
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
  headertitlecentercenterflex1row: { 
    flex:1,
    backgroundColor: '#aaa',
    alignItems: 'center',
    justifyContent: 'center',
    flexDirection:'row', 
  },  
  leftleftflex1rownobg: { 
    flex:1,
    alignItems: 'left',
    justifyContent: 'left',
    flexDirection:'row', 
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




