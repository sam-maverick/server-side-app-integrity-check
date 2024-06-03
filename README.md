# Server-side app integrity check Nodejs library

This is a Node.js module that is to be used in your app server to validate Android's app integrity tokens (or, attestation objects) sent by your clients. It can validate tokens of Android's [Play Integrity API](https://developer.android.com/google/play/integrity/overview) (either classic or standard requests). It does NOT support Android's deprecated SafetyNet API.

It is your responsibility to handle Google/Apple server outages (as those servers must inevitably be used in the attestation requests), to design your platform logic to conform to the API request rate limits such as onboarding users gradually (in iOS, attestation should be [typically be performed once per user and device](https://developer.apple.com/documentation/devicecheck/preparing_to_use_the_app_attest_service); Android's Play Integrity requests are [throttled to 10,000](https://developer.android.com/google/play/integrity/classic#compare-standard) per app platform per day in the lowest tier among other limits), and to have a plan on how to handle clients that do not meet the maximum standards (for example, rooted devices or with Play Protect disabled), among other considerations.

If you need a library to generate attestation tokens on the client side (the app running on the users' devices), then check this out:
Standard requests: https://github.com/sam-maverick/app-integrity-android-standard
Classic requests: https://github.com/jeffDevelops/expo-app-integrity

If you need a library to check iOS attestations from the server side, then check this out: [https://github.com/srinivas1729/appattest-checker-node](https://github.com/srinivas1729/appattest-checker-node)

This work (code and documentation) is based on [https://github.com/herzhenr/spic-server](https://github.com/herzhenr/spic-server). See the attached license.



## Setup

#### Set up a Google Cloud Project

- Create a new [Google Cloud](https://console.cloud.google.com) Project
- Navigate to **APIs & Services** -> **Enabled APIs & Services** -> **Enable APIs & Services** and enable the Play Integrity API there
- Within the Play Integrity API page navigate to **Credentials** -> **Create Credentials** -> **Service Account**. Set a name there and leave the rest on default values.
- Navigate to **Keys** -> **Add Key** -> **Create New Key**
  Go to Keys -> Add Key -> Create new key. The JSON file that downloads automatically has the contents verbatim you will later need for the environment variable.

#### Set up a Google Play Console Project
- Create a new [Google Play Console](https://play.google.com/console/) Project.
- Within Google Play Console, link the new Google Cloud Project to it.
- To obtain the decryption and verification keys, navigate within th Google Play Console to **Release** -> **Setup** -> **AppIntegrity** -> **Response encryption**
- Click on **Change** and choose **Manage and download my response encryption keys** if you plan to verify attestations on your server instead of offloading work to Google servers.
- Follow the on-screen instructions to create a private-public key pair in order to download the encrypted keys.

#### Environment variables

Define the necessary environment variables in a `.env` file at the root of your project.
Use `example.env` as a sample. Don't forget to rename it to `.env`



## Installation

```
npm install server-side-app-integrity-check
```



## Usage

If, for example, you have a CommonJS project, you can use the library in this way:

#### `decryptPlayIntegrity()`

Decrypt the token received from the client, to an object containing the raw attestation data.

```
let attestcheckerlibrary = await import('server-side-app-integrity-check');

decryptedToken = await attestcheckerlibrary.decryptPlayIntegrity(
  token,  // token the client received from the PlayIntegrity Server in the previous step
  mode    // Set to 'server' to check integrity locally. Set to 'google' to offload the check to Google servers
);
```

#### `verifyPlayIntegrity()`

Check the decrypted token validity. It checks that the nonce is correct, that the signatures are correct, and that all the fields indicate that the attestation is correct.

```
let attestcheckerlibrary = await import('server-side-app-integrity-check');

/** Check the token validity. 
*   It checks that the nonce is correct and that all the fields indicate that the attestation is correct.
*   'none_truth' is the ground truth of the nonce as stored by your app server
*/
attestationresult = attestcheckerlibrary.verifyPlayIntegrity(
  decryptedToken, // as obtained from decryptPlayIntegrity()
  nonce_truth     // ground truth of the nonce as stored by your app server
);
```

Possible return values for `attestationresult`:

`{status: "fail", message: "Some explanatory message here", decryptedToken: "Here you will have the decrypted token"}`   :=
Attestation was not successful. The app integrity is compromised or some other condition has occurred. Bear in mind that attestations will likely not succeed if an Android device has been rooted or if the device does not meet maximum standards.

`{status: "error", message: "Some explanatory message here", decryptedToken: "Here you will have the decrypted token"}`   :=
An unexpected error has occurred. Do not forget to also embrace the sample code above within a try-catch clause to capture any errors throwed by the module.

`{status: "success", message: "Some explanatory message here", decryptedToken: "Here you will have the decrypted token"}`   :=
Nice! The client passed the attestation. You will get a 'success' only if high security standards are met in the device environment. If you want to lower the standards, you will need to modify the code of this library yourself.

​    

## Acknowledgements

The project that gave rise to these results received the support of a fellowship from ”la Caixa” Foundation (ID 100010434). The fellowship code is LCF/BQ/DI22/11940036. This work was also supported by FCT through the LASIGE Research Unit (UIDB/00408/2020 and UIDP/00408/2020).

​    

## License

This work is licensed under the MIT license. See [LICENSE](LICENSE) for details.