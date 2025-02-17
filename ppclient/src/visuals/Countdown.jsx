
import { Text, View } from 'react-native';
import { React, useState, useEffect } from 'react';
import { styles } from './myVisualsLibrary.jsx';
import { LogMe, FromTimeSpanToHumanReadableString } from '../myGeneralLibrary.jsx';


var startingTimeMs;
var intervalTimer;


export const CountdownComponent = (props) => {

    const [initStatus, setInitStatus] = useState({ key: 'init' });
    const [visuals, setVisuals] = useState({});


    const UpdateBar = async() => {
        let remainingTimeLapse = props.countdownInitialTimerMs - ( Date.now() - startingTimeMs );
        let percentage = (100*remainingTimeLapse)/props.countdownInitialTimerMs;

        setVisuals({
            remainingTimeHR: FromTimeSpanToHumanReadableString(remainingTimeLapse),
            percentageStyle: { width: percentage+'%' },
            percentageValue: percentage,
        });
    }


    useEffect( () => {  // This is executed when the component is reloaded
        async function didMount() { // Do not change the name of this function
            // Do stuff
            LogMe(2, 'useEffect of CountdownComponent invocation');  

            startingTimeMs = Date.now();

            UpdateBar();

            intervalTimer = setInterval(() => {
                UpdateBar();
            }, 150);   

        }

        didMount();  // If we want useEffect to be asynchronous, we have to define didMount as async and call it right after
        return async function didUnmount() { // Do not change the name of this function
          // Cleanup tasks
          LogMe(1, 'useEffect of CountdownComponent cleanup');
          clearInterval(intervalTimer);
        };

    }, []);  // App.js does not have props

    // This function will be called both when a deep link starts the app and when a deep link foregrounds the app
    async function ComponentRefresh() {  // Invoked every time this screen is loaded

        LogMe(2, 'Refreshing CountdownComponent Component');
        if (initStatus.key === 'init') {
            LogMe(1, 'Initialising CountdownComponent Component');
            initStatus.key = 'updated'; //update without rendering
            //initStatus({ key:'updated'}); //update with rendering
            // This will reach only on the first time the scren is loaded    
        }

    }

    ComponentRefresh();

    if (visuals.percentageValue > 15) {
        return(
            <View style={styles.leftleftlinebg}>
                <View style={visuals.percentageStyle}>
                    <View style={styles.leftleftline}>
                        <Text>  {visuals.remainingTimeHR}</Text>
                    </View>
                </View>
            </View>
        );    
    } else {
        return(
            <View style={styles.leftleftlinebg}>
                <View style={visuals.percentageStyle}>
                    <View style={styles.leftleftline}>
                        <Text> </Text>
                    </View>
                </View>
                <Text style={{color: 'white'}}>  {visuals.remainingTimeHR}</Text>
            </View>
        );    
    }

}

