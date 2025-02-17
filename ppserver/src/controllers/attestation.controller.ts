import { Controller, Post, Req } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';

import { AppService } from '../app.service';
import DevicesModel from '../middleware/database/schemas/Device';
import PicturesModel from '../middleware/database/schemas/Picture';
import { PARAM_LENGTH_TOKENS, MINIMUM_ANDROID_API_LEVEL, ANDROID_CHECK_MODE, 
    IOS_SUPPORTED_VERSIONS, IOS_IS_DEVELOPMENT_ENVIRONMENT, MAX_TOTAL_DELAY_MS, PARAM_TEST_MODE } from '../parameters';
import { LogMe, GenerateRandomString, isAnInteger, EncodeFromB64ToBuffer, EncodeFromBufferToB64, EncodeFromB64ToBinary, EncodeFromBinaryToB64 } from '../serverLibrary';

import { CheckPlayIntegrity } from '../attestationapi/androidintegrityapi';
import { CheckAppAttestation, CheckAppAssertion } from '../attestationapi/iosintegrityapi';

import { DecryptThings } from '../cryptography/cryptoFunctions';


if (PARAM_TEST_MODE) {
    // We skip LogMe to make sure that the message is displayed
    console.log();
    console.log('\x1b[31m%s\x1b[0m', '!!!!!!  WARNING  ----  WARNING  ---- WARNING  !!!!!!');    
    console.log();
    console.log('\x1b[31m%s\x1b[0m', 'PARAM_TEST_MODE has been set to true. This means that this PP server will accept all attestation requests without verifying them.');
    console.log('\x1b[31m%s\x1b[0m', 'Use this option only in test/dev/integration environments. Do not use in production!!');
    console.log();
}


function CheckIosVersion(platformVersion: string) {
    const semver = require('semver');
    if ( ! semver.satisfies(platformVersion, IOS_SUPPORTED_VERSIONS)) {
        return {status: "fail", message: "Your device does not have the minimum version or patch level for the operating system. Please update your iOS version."};
    } else {  // Successful
        return {status: "success", message: "Attestation successful."};
    }
}



function checkRequestPlatformAndType (platformType: string, requestType: string) {
    if ( !
        (
        (platformType === 'android')
        ||
        (platformType === 'ios')
        )
       ) {
        return {
            result: false,
            message: 'Your platformType is not supported. Only \'android\' and \'ios\' platforms are supported.',
        };
    } else if ( platformType === 'android' && 
                    (
                        requestType !== 'classic'
                        &&
                        requestType !== 'standard'
                    )
              ) {
        return {
            result: false,
            message: 'In Android, only \'standard\' and \'classic\' are supported as requestType.',
        };
    } else if ( platformType === 'ios' && 
                    (
                        requestType !== 'attestation'
                        &&
                        requestType !== 'assertion'
                    )
              ) {
        return {
            result: false,
            message: 'In iOS, only \'attestation\' and \'assertion\' are supported as requestType.',
        };
    } else {
        return {
            result: true,
            message: '',
        };
    }
}


@Controller('attestations')
export class AttestationController {
  constructor(private readonly appService: AppService) {}



  @Post('/submitAttestationTokenToServer')
  async submitAttestationTokenToServer(@Req() req) {

    LogMe(0, 'Controller: attestations/submitAttestationTokenToServer: Starting');

    LogMe(2, 'Request contents:');
    LogMe(2, JSON.stringify(req.body));
    // NOTE: req.body.requestType is relevant only when platform is android

    /**
     * Per-request global parameters:
     * req.body.{environment|cookie|platformVersion|platformType|encryptedKeyB64}
     * Parameters that go in an array, as every request contains 1 or 2 subrequests:
     * req.body.{requestType|token}
     */

    // Perform all checks

    const deviceObject = await DevicesModel.findOne({'cookie': req.body?.cookie});

    // Check environment parameter
    if( ! (req.body?.environment === 'PPIntegrity' || req.body?.environment === 'PPEnrollment' || req.body?.environment === 'PPWrapOps')) {
        /**
         * PPIntegrity: On-demand integrity tests. No pre-requirements
         * PPEnrollment: Enrollment of devices to the PP platform. All devices must enroll prior to using PPWrapOps
         * PPWrapOps: Integrity verification to get a credential. This is to decrypt private pictures.
         */
        return {isSuccessful: false, resultMessage: 'Environment must be PPIntegrity or PPEnrollment.'};
    }

    // Check if cookie is found
    if( ! deviceObject) {
        return {isSuccessful: false, resultMessage: 'Cookie not found.'};
    }

    // Check that there is a platformVersion field
    if ( ! req.body?.platformVersion) {
        return {isSuccessful: false, resultMessage: 'Each request must contain a platformVersion field.'};
    }

    // Check that there is a platformType field
    if ( ! req.body?.platformType) {
        return {isSuccessful: false, resultMessage: 'Each request must contain a platformType field.'};
    }
    
    // Check that there is a subrequests field
    if ( ! req.body?.subrequests) {
        return {isSuccessful: false, resultMessage: 'Each request must contain a subrequests field.'};
    }
    // And check that that field is an array
    if ( ! Array.isArray(req.body?.subrequests)) {
        return {isSuccessful: false, resultMessage: 'The subrequests field must be an array. You provided: ' + typeof(req.body?.subrequests) + '.'};
    }
    // And that there are either 1 or 2 elements in the array
    if (req.body.subrequests.length < 1 || req.body.subrequests.length > 2) {
        return {isSuccessful: false, resultMessage: 'Each request must contain either 1 or 2 subrequests. You provided ' + req.body.subrequests.length + '.'};
    }

    //Specific checks for PPWrapOps
    if(req.body.environment === 'PPWrapOps') {
        if (req.body.platformType === 'android') {
        //#*#// Check that there are 2 subrequests and that they are diverse (we already checked that they correspond to either classic or standard attestation, so if they are diverse, they are one of each)
            if (req.body.subrequests.length != 1) {//#*#
                return {isSuccessful: false, resultMessage: 'PPWrapOps failed. For android, a request can only contain a subrequest.'};//#*#
            }//#*#
            //#*#if (req.body.subrequests.length != 2) {
            //#*#    return {isSuccessful: false, resultMessage: 'PPWrapOps failed. For android, you need to submit a request that contains two subrequests.'};
            //#*#}
            //#*#if (req.body.subrequests[0].requestType == req.body.subrequests[1].requestType) {
            //#*#    return {isSuccessful: false, resultMessage: 'PPWrapOps failed. Each of the subrequests must have a different requestType (one standard, and one classic).'};
            //#*#}
            if (req.body.subrequests[0].requestType != 'standard') {//#*#
                return {isSuccessful: false, resultMessage: 'PPWrapOps failed. For android, the subrequest must be of standard type.'};//#*#
            }//#*#
        } else if (req.body.platformType === 'ios') {
            if (req.body.subrequests.length != 1) {
                return {isSuccessful: false, resultMessage: 'PPWrapOps failed. For ios, a request can only contain a subrequest.'};
            }
            if (req.body.subrequests[0].requestType != 'assertion') {
                return {isSuccessful: false, resultMessage: 'PPWrapOps failed. For ios, the subrequest must be of assertion type.'};
            }
        }  // No need for an else because platformType will be checked below
    }


    // CHECK EACH OF THE SUBREQUESTS

    let i = 0;

    while (i < req.body.subrequests.length) {

        LogMe(0, 'Processing subrequest #'+i+' ['+String(req.body?.subrequests[i]?.requestType)+']');

        const advicemsg = '\n\nUpdate your system and your PP client app, check that your device is not rooted/jailbroken, enable all security protections, and make sure you downloaded the app from the official store. Then try again.'; 

        const issueidmsg = req.body.subrequests.length>1 ? 'There was an isue with subrequest #'+i+' ['+String(req.body?.subrequests[i]?.requestType)+']: ' : '';

        const resultVerifyRequest = checkRequestPlatformAndType(String(req.body.platformType), String(req.body?.subrequests[i]?.requestType));
        if ( ! resultVerifyRequest.result) {
            return {isSuccessful: false, resultMessage: issueidmsg+resultVerifyRequest.message};
        }
    
        // Check that a token is provided
        if ( ! req.body?.subrequests[i]?.token) {
            return {isSuccessful: false, resultMessage: issueidmsg+'No token was provided.'+advicemsg};
        }
    
        // Cross-consistency check, and existence of nonce check
        if ( deviceObject.nonces[req.body.platformType+'_'+req.body.subrequests[i].requestType].nonce === '' ) {
            return {isSuccessful: false, resultMessage: issueidmsg+'platformType or requestType inconsistency. You are submitting a token for which a nonce was not generated.'+advicemsg};
        }
    
        // Single-consumption check for the nonce
        if ( deviceObject.nonces[req.body.platformType+'_'+req.body.subrequests[i].requestType].consumed === true ) {
            return {isSuccessful: false, resultMessage: issueidmsg+'This nonce has already been consumed.'+advicemsg};
        }
    
    
        // ANDROID ----------------------------------------------------------------------------------------------
    
        if (req.body.platformType === 'android') {
    
            let myAndroidCheckMode = ANDROID_CHECK_MODE;
            if (req.body.subrequests[i].requestType === 'standard') {
                myAndroidCheckMode = 'google';  // In standard requests, only 'google' mode is supported by Google. Local on-server verification of tokens is not supported in the official API.
            }
    
            let resultOperation = undefined;            
            if (PARAM_TEST_MODE) {
                resultOperation = {status: 'success', message: 'Successful'};
            } else {
                resultOperation = await CheckPlayIntegrity(
                    req.body.subrequests[i].token, 
                    deviceObject.nonces[req.body.platformType+'_'+req.body.subrequests[i].requestType].nonce, 
                    myAndroidCheckMode, 
                    req.body.subrequests[i].requestType
                );   
            }
    
            LogMe(2, 'Result of the operation #'+i+': '+JSON.stringify(resultOperation));
    
            // Check attestation
            if (resultOperation.status !== 'success') {
                return {isSuccessful: false, resultMessage: issueidmsg+resultOperation.message+advicemsg};
            }
    
            if (resultOperation.status === 'success') {
                // Check things after attestation. These things are not attested directly but indirectly.
                // Check version
                if( ! ((typeof req.body.platformVersion) === 'number')) {  // Is of number type?
                    return {isSuccessful: false, resultMessage: issueidmsg+"Wrong type for platformVersion. We expected number. We found "+(typeof req.body.platformVersion)+"."+advicemsg};
                } else if (req.body.platformVersion < MINIMUM_ANDROID_API_LEVEL) {
                    return {isSuccessful: false, resultMessage: issueidmsg+"OS version is unsupported. Expected >= " + MINIMUM_ANDROID_API_LEVEL + ". Found " + req.body.platformVersion + "."+advicemsg};
                }
                // Check maximum delay
                if (Date.now() - deviceObject.nonces[req.body.platformType + '_' + req.body.subrequests[i].requestType].timestamp > MAX_TOTAL_DELAY_MS[req.body.platformType + '_' + req.body.subrequests[i].requestType]) {
                    return {isSuccessful: false, resultMessage: issueidmsg+"Request too old. Took too long from generating the nonce on our server to checking it on our server."+advicemsg};
                }
                // Note: We do not attest device type (tablet, phone, ...)
            }
    
    
    
        // iOS ----------------------------------------------------------------------------------------------
    
        } else if (req.body.platformType === 'ios') {
    
            if (req.body.subrequests[i].requestType === 'attestation') {

                // Check that a KeyId is provided
                if ( ! req.body?.subrequests[i]?.keyId) {
                    return {isSuccessful: false, resultMessage: issueidmsg+'No KeyId was provided.'+advicemsg};
                }
                
                let resultOperation = undefined;            
                if (PARAM_TEST_MODE) {
                    resultOperation = {
                        status: 'success', 
                        message: 'Attestation warmup successful.',
                        publicKeyPem: 'nothing',
                        receipt: 'noting',
                    };
                } else {    
                    resultOperation = await CheckAppAttestation(
                        req.body.subrequests[i].token, 
                        deviceObject.nonces[req.body.platformType+'_'+req.body.subrequests[i].requestType].nonce, 
                        req.body.subrequests[i].keyId
                    );
                }
    
                LogMe(2, 'Result of the operation #'+i+': '+JSON.stringify(resultOperation));
    
                // Check attestation
                if (resultOperation.status !== 'success') {
                    return {isSuccessful: false, resultMessage: issueidmsg+resultOperation.message+advicemsg};
                }
    
                // Check things after attestation. These things are not attested directly but indirectly.
    
                // Check version
                let versionCheckResult = CheckIosVersion(req.body.platformVersion);
                if (versionCheckResult.status !== 'success') {
                    return {isSuccessful: false, resultMessage: issueidmsg+versionCheckResult.message+advicemsg};
                }
    
                // Check maximum delay
                if (Date.now() - deviceObject.nonces[req.body.platformType + '_' + req.body.subrequests[i].requestType].timestamp > MAX_TOTAL_DELAY_MS[req.body.platformType + '_' + req.body.subrequests[i].requestType]) {
                    return {isSuccessful: false, resultMessage: issueidmsg+"Request too old. Took too long from generating the nonce on our server to checking it on our server."+advicemsg};
                }
    
                // Note: We do not attest device type (iPad, iPhone, Mac, ...)
                // Looks like Macs are not supported anyway. See: https://developer.apple.com/forums/thread/682488
    
                // Save publicKey and signCount for this device (sample code).
                const updateResult = await DevicesModel.updateOne(
                    {cookie: req.body.cookie},
                    {
                        iosPublicKeyPEM: resultOperation.publicKeyPem, 
                        iosReceipt: resultOperation.receipt, 
                        iosSignCount: 0,
                    }
                );
    
                if ( ! updateResult) {
                    return {isSuccessful: false, resultMessage: issueidmsg+"DB error when updating your request."+advicemsg};
                }
    
    
    
            } else if (req.body.subrequests[i].requestType === 'assertion') {
    
                if ( ! deviceObject?.iosPublicKeyPEM || deviceObject.iosPublicKeyPEM=='') {
                    // The user previously got a nonce but did not provide an attestation
                    return {isSuccessful: false, resultMessage: issueidmsg+"You need to submit a successful attestation before requesting an assertion."+advicemsg};
                }
    
                let resultOperation = undefined;
                if (PARAM_TEST_MODE) {
                    resultOperation = {
                        status: 'success', 
                        message: 'Assertion successful.', 
                        iosSignCount: deviceObject.iosSignCount + 1,
                    };
                } else {    
                    resultOperation = await CheckAppAssertion(
                        req.body.subrequests[i].token, 
                        deviceObject.nonces[req.body.platformType+'_'+req.body.subrequests[i].requestType].nonce, 
                        deviceObject.iosPublicKeyPEM,
                        deviceObject.iosSignCount
                    );
                }
    
                LogMe(2, 'Result of the operation #'+i+': '+JSON.stringify(resultOperation));
    
                // Check assertion
                if (resultOperation.status !== 'success') {
                    return {isSuccessful: false, resultMessage: issueidmsg+resultOperation.message+advicemsg};
                }
    
                // Check things after assertion. These things are not attested directly but indirectly.
    
                // Check version
                let versionCheckResult = CheckIosVersion(req.body.platformVersion);
                if (versionCheckResult.status !== 'success') {
                    return {isSuccessful: false, resultMessage: issueidmsg+versionCheckResult.message+advicemsg};
                }
                // Check maximum delay
                if (Date.now() - deviceObject.nonces[req.body.platformType + '_' + req.body.subrequests[i].requestType].timestamp > MAX_TOTAL_DELAY_MS[req.body.platformType + '_' + req.body.subrequests[i].requestType]) {
                    return {isSuccessful: false, resultMessage: issueidmsg+"Request too old. Took too long from generating the nonce on our server to checking it on our server."+advicemsg};
                }
    
                // Note: We do not attest device type (iPad, iPhone, Mac, ...)
                // Looks like Macs are not supported anyway. See: https://developer.apple.com/forums/thread/682488
    
                // Save publicKey and signCount for this device (sample code).
                const updateResult = await DevicesModel.updateOne(
                    {cookie: req.body.cookie},
                    {iosSignCount: resultOperation.iosSignCount}
                );
    
                if ( ! updateResult) {
                    return {isSuccessful: false, resultMessage: issueidmsg+"DB error when updating your request."};
                } 
            }
    
        }
    
        // Mark nonce as consumed
        const updateResult = await DevicesModel.updateOne(
            {cookie: req.body.cookie},
            [{ $addFields: { nonces: { [req.body.platformType+'_'+req.body.subrequests[i].requestType]: {consumed: true} } } }]
        );
        if ( ! updateResult) {
            return {isSuccessful: false, resultMessage: 'DB error when updating the consumption status of the nonce.'};
        }

        i++;  // Check next subrequest

        LogMe(0, 'Subrequest processed');
    }
    
    // All subrequests were successful
    // Build the response accordingly to the environment

    if(req.body.environment === 'PPWrapOps') {
        try {
            const fullDataObject = await DecryptThings(req.body.requestDataObject);
            LogMe(1, 'fullDataObject?.to_server_data: '+fullDataObject?.to_server_data);

            // Enforce privacy policies here
            //

            // Expiration Date
            let currentDate = Date.now();
            if ( ! fullDataObject?.to_server_data?.privacyPolicies?.ExpirationDate) {
                let msg = 'Error: Missing to_server_data.privacyPolicies.ExpirationDate field.';
                LogMe(1, msg);
                return {isSuccessful: false, resultMessage: msg};
            }
            if ((typeof fullDataObject.to_server_data.privacyPolicies.ExpirationDate) !== 'number') {
                let msg = 'Error: to_server_data.privacyPolicies.ExpirationDate field is not a number.';
                LogMe(1, msg);
                return {isSuccessful: false, resultMessage: msg};
            }
            if (currentDate > fullDataObject.to_server_data.privacyPolicies.ExpirationDate) {
                let msg = 'Access denied: Attempting to open a private picture past the expiration date.';
                LogMe(1, msg + ' Expiration date is ' + fullDataObject.to_server_data.privacyPolicies.ExpirationDate.toString());
                return {isSuccessful: false, resultMessage: msg, pictureID: fullDataObject.to_server_data.pictureId};        
            }

            // View Once
            if ( ! fullDataObject?.to_server_data?.privacyPolicies?.ViewOnce) {
                let msg = 'Error: missing to_server_data.privacyPolicies.ViewOnce field.';
                LogMe(1, msg);
                return {isSuccessful: false, resultMessage: msg};
            }
            if ( fullDataObject.to_server_data.privacyPolicies.ViewOnce!=='Yes' && fullDataObject.to_server_data.privacyPolicies.ViewOnce!=='No' ) {
                let msg = 'Error: to_server_data.privacyPolicies.ViewOnce field must be either `Yes` or `No`.';
                LogMe(1, msg);
                return {isSuccessful: false, resultMessage: msg};
            }
            if ( ! fullDataObject?.to_server_data?.pictureId) {
                let msg = 'Error: Missing to_server_data.pictureId field.';
                LogMe(1, msg);
                return {isSuccessful: false, resultMessage: msg};
            }
            if (fullDataObject.to_server_data.pictureId=='') {
                let msg = 'Error: to_server_data.pictureId field cannot be empty.';
                LogMe(1, msg);
                return {isSuccessful: false, resultMessage: msg};
            }
            if ((typeof fullDataObject.to_server_data.pictureId) !== 'string') {
                let msg = 'Error: to_server_data.pictureId field is not a string.';
                LogMe(1, msg);
                return {isSuccessful: false, resultMessage: msg};
            }
            if (fullDataObject.to_server_data.pictureIdSenderPrivate=='') {
                let msg = 'Error: to_server_data.pictureIdSenderPrivate field cannot be empty.';
                LogMe(1, msg);
                return {isSuccessful: false, resultMessage: msg};
            }
            if ((typeof fullDataObject.to_server_data.pictureIdSenderPrivate) !== 'string') {
                let msg = 'Error: to_server_data.pictureIdSenderPrivate field is not a string.';
                LogMe(1, msg);
                return {isSuccessful: false, resultMessage: msg};
            }
            if (fullDataObject.to_server_data.privacyPolicies.ViewOnce==='Yes') {
                const pictureObject = await PicturesModel.findOne({'pictureId': fullDataObject.to_server_data.pictureId});
                if (pictureObject) {
                    let msg = 'Access denied: Attempting to re open a private picture that is set to view only once.';
                    LogMe(1, msg);
                    return {isSuccessful: false, resultMessage: msg, pictureID: fullDataObject.to_server_data.pictureId};    
                }
            }

            const pictureObjectCheckUnsent = await PicturesModel.findOne({
                'pictureIdSenderPrivate': fullDataObject.to_server_data.pictureIdSenderPrivate,
                'unsent': true,
            });
            if (pictureObjectCheckUnsent) {
                let msg = 'Access denied: This private picture has been unsent by the sender.';
                LogMe(1, msg);
                return {isSuccessful: false, resultMessage: msg, pictureID: fullDataObject.to_server_data.pictureId};    
            }

            const mynewpicture = await PicturesModel.updateOne(
                {
                    pictureId: fullDataObject.to_server_data.pictureId, 
                    pictureIdSenderPrivate: fullDataObject.to_server_data.pictureIdSenderPrivate,
                },
                { $setOnInsert: { // If an update operation with upsert: true results in an insert of a document, then $setOnInsert assigns the specified values to the fields in the document. If the update operation does not result in an insert, $setOnInsert does nothing.
                    pictureId: fullDataObject.to_server_data.pictureId, 
                    pictureIdSenderPrivate: fullDataObject.to_server_data.pictureIdSenderPrivate, 
                    reported: false,
                    unsent: false,
                    viewed: true,
                      } },
                {upsert: true}  // Creates a new document if none was updated
            );
            if (!mynewpicture) {
                return {isSuccessful: false, resultMessage: 'Could not insert picture with ID='+fullDataObject.to_server_data.pictureId+' into the database'}; 
            }

            // Success
            LogMe(0, 'Controller: attestations/submitAttestationTokenToServer: Finished');
            return {
                isSuccessful: true,
                resultMessage: 'Successful',
                replyDataObject: {
                    stage1: fullDataObject.stage1,
                    privacyPolicies: fullDataObject.to_server_data.privacyPolicies,  
                    pictureId: fullDataObject.to_server_data.pictureId,
                },
            };
        } catch (err) {
            LogMe(1, 'Error when processing or decrypting '+err.message);
            return {isSuccessful: false, resultMessage: 'Error when processing or decrypting data related to the protected picture. For security reasons, we can\'t provide details here. Contact the PP server administrators for more info.'};
        }       
    } else {
        // Just inform about success
        return {
            isSuccessful: true,
            resultMessage: 'Successful',
        };
    }    
  }


    @Post('/reportMaterial')
    async reportMaterial(@Req() req) {

        // ToDo: Prevent brute force attacks
        // Introduce a delay?
        // Ask to do attestation?

        LogMe(0, 'Controller: attestations/reportMaterial: Starting');
        LogMe(0, 'Controller: attestations/reportMaterial: req.body.pictureID='+req.body.pictureID);

        // We add the viewed:true condition to prevent recipients from reporting pictures not viewed, e.g., when the sender unsends them before the recipients opens
        const pictureObject = await PicturesModel.updateOne(
            {pictureId: req.body.pictureID, viewed: true},
            [{ $addFields: { reported: true  } }]
        );

        if ( ! pictureObject) {
            return {isSuccessful: false, resultMessage: 'Could not update picture with ID='+req.body.pictureID+' in the database'}; 

        }

        // We don't verbose the details of the result, for privacy. This way, the sender cannot know if the picture was seen or not.
        return {
            isSuccessful: true,
            resultMessage: 'If the pictureID was present in our database, it has been marked as reported.',
        };

    }


    // This method has not been tested yet
    @Post('/unsendMaterial')
    async unsendMaterial(@Req() req) {

        // ToDo: Prevent brute force attacks
        // Introduce a delay?
        // Ask to do attestation?

        LogMe(0, 'Controller: attestations/unsendMaterial: Starting');
        LogMe(2, 'Controller: attestations/unsendMaterial: req.body.pictureIDSenderPrivate='+req.body.pictureIDSenderPrivate);
        LogMe(2, 'Controller: attestations/unsendMaterial: req.body.pictureID='+req.body.pictureID);

        const pictureObject = await PicturesModel.updateOne(
            {pictureId: req.body.pictureID, pictureIdSenderPrivate: req.body.pictureIDSenderPrivate},
            [{ $addFields: { 
                pictureId: req.body.pictureID, 
                pictureIdSenderPrivate: req.body.pictureIDSenderPrivate,
                unsent: true,
              } }],
            {upsert: true}  // Creates a new document if none was updated
        );

        if ( ! pictureObject) {
            return {isSuccessful: false, resultMessage: 'Could not update picture with ID='+req.body.pictureID+' in the database'}; 

        }

        return {
            isSuccessful: true,
            resultMessage: 'If the pictureID was present in our database, it has been marked as unsent.',
        };

    }


    @Post('/getNonceFromServer')
    async getNonceFromServer(@Req() req) {

        LogMe(0, 'Controller: attestations/getNonceFromServer: Starting');

        let resultVerifyRequest = checkRequestPlatformAndType(req.body.platformType, req.body.requestType);
        if ( ! resultVerifyRequest.result) {
            return {
                isSuccessful: false,
                resultMessage: resultVerifyRequest.message,
            };
        }

        let existingDeviceObject = await DevicesModel.findOne({'cookie': req.body.cookie });

        const myNonce = GenerateRandomString(PARAM_LENGTH_TOKENS);
        LogMe(1, 'Nonce: '+myNonce);

        if ( ! existingDeviceObject) {  // Device unseen before
            LogMe(1, 'Controller: attestations/getNonceFromServer Device unseen before');

            const myCookie = GenerateRandomString(PARAM_LENGTH_TOKENS);
            LogMe(1, 'Controller: attestations/getNonceFromServer New cookie='+myCookie);
    
            let newDeviceDocument = {
                nonces: {
                    android_classic: {
                        nonce: '',
                        timestamp: 0,
                        consumed: true,
                    },
                    android_standard: {
                        nonce: '',
                        timestamp: 0,
                        consumed: true,
                    },
                    ios_attestation: {
                        nonce: '',
                        timestamp: 0,
                        consumed: true,
                    },
                    ios_assertion: {
                        nonce: '',
                        timestamp: 0,
                        consumed: true,
                    },
                },
                cookie: myCookie,
                iosIsDevelopment: IOS_IS_DEVELOPMENT_ENVIRONMENT,
                iosPublicKeyPEM: '',
                iosReceipt: '',
            };

            newDeviceDocument.nonces[req.body.platformType+'_'+req.body.requestType] = 
                { nonce: myNonce,
                  timestamp: Date.now(),
                  consumed: false,
                };
    
            const mynewdevice = await DevicesModel.create(newDeviceDocument);
    
            if(mynewdevice) {
                return {
                    isSuccessful: true,
                    resultMessage: 'Nonce and cookie created successfully.',
                    nonce: myNonce,
                    cookie: myCookie,
                };
            } else {
                return {
                    isSuccessful: false,
                    resultMessage: 'There has been an error.',
                };
            }
    
        } else {  // Device seen before
            LogMe(1, 'Controller: attestations/getNonceFromServer Device seen before, welcome back');
            LogMe(1, 'Controller: attestations/getNonceFromServer cookie: '+req.body.cookie);
            LogMe(1, 'Controller: attestations/getNonceFromServer requestType: '+req.body.requestType);

            const updateResult = await DevicesModel.updateOne(
                {cookie: req.body.cookie},
                [{ $addFields: { nonces: { [req.body.platformType+'_'+req.body.requestType]: {nonce: myNonce, timestamp: Date.now(), consumed: false} }  } }]
                );

            if(updateResult) {
                LogMe(0, 'Controller: attestations/getNonceFromServer: Finished');
                return {
                    isSuccessful: true,
                    resultMessage: 'Nonce created successfully onto existing cookie.',
                    nonce: myNonce,
                    cookie: existingDeviceObject.cookie,
                };
            } else {
                return {
                    isSuccessful: false,
                    resultMessage: 'There has been an error.',
                };
            }

        }


    }
  
}
