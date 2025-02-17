// Do not import custom libraries from here

import * as SecureStorage from 'expo-secure-store';
import { LogMe } from '../myGeneralLibrary.jsx';

/**
 * Key: The key to associate with the stored value. Keys may contain alphanumeric characters, ., -, and _.
 * Value: The value to store. Size limit is 2048 bytes.
 * Options: See https://docs.expo.dev/versions/latest/sdk/securestore/#securestoreoptions
 */

/**
 * 
 * @param {Object} params An object containing key and options. Key is a string, and options is an object
 * @returns Promise with the object value. It resolves with null if there is no entry for the given key or if the key has been invalidated.
 */
export async function load (params) {
    LogMe(1, 'StorageApi.js: load: '+params.key);  
    const data = await SecureStorage.getItemAsync(params.key, params.options);
    let retval;
    if (data == '') {
        retval = {};
    } else {
        retval = JSON.parse(data);
    }
    LogMe(1, 'StorageApi.js: save finished');
    return retval;
}

/**
 * 
 * @param {Object} params An object containing key, value and options. Key is a string, value is an object, and options is an object
 * @returns Promise that resolves if successful
 */
export async function save (params) {
    LogMe(1, 'StorageApi.js: save: ' + params.key);  
    const retval = await SecureStorage.setItemAsync(params.key, JSON.stringify(params.value), params.options);
    LogMe(1, 'StorageApi.js: save finished');
    return retval;
}

/**
 * 
 * Deletes a key, if it exists. Rejects Promise if the key exists but cannot be deleted, or if the API
 * gives some error
 * @param {Object} params An object containing key and options. Key is a string, and options is an object
 * @returns Object
 */
export async function deleteKey (params) {
    LogMe(1, 'StorageApi.js: deleteKey: '+params.key);  
    const value = await SecureStorage.getItemAsync(params.key, params.options);
    if (value !== null) {
        const retval = await SecureStorage.deleteItemAsync(params.key, params.options);
        LogMe(1, 'StorageApi.js: deleteKey finished');
        return retval;
    }
}