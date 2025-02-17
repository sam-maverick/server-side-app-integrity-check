const { createRunOncePlugin, withInfoPlist } = require('expo/config-plugins');



const withInfoPlistHttpConfigurations = (config, id) => {
  return withInfoPlist(config, async(config) => {

    console.warn('withInfoPlistHttpConfigurations started');

    const fs = require('fs');
// /*

    // Check: ../src/parameters
    const PARAM_SERVER_PINNED_DOMAIN = 'localnetwork.org';

    // This is a public key hash of a throw-away CA (a CA we generated and deleted)
    // This is because TrustKit obliges us to specify a backup CA
    const throwAwayCaPubkeyHash = 'BOXZ+XSbXpFtJgXb9X8uUWhx+YA8dX3y1nqFUmez3UE=';



    // Get SHA256 hash of the public key of the CA, in BASE64format

    const pubkey256hashb64 = fs.readFileSync('assets/custom/ca_cert_pubkey_sha256_base64.txt', {encoding: 'utf8'});

    //console.warn('pubkey256hashb64=*'+pubkey256hashb64+'*');
    




    // Modifications AppDelegate.mm

    let AppDelegateOriginalContents = fs.readFileSync('ios/ppclient/AppDelegate.mm', {encoding: 'utf8'});

    if ( ! AppDelegateOriginalContents.includes('kTSKPinnedDomains: @{')) {
      let AppDelegateModifiedContents = AppDelegateOriginalContents.replace('  self.moduleName = @"main";', '\
  NSDictionary *trustKitConfig =\n\
  @{\n\
    kTSKSwizzleNetworkDelegates: @YES,\n\
    kTSKPinnedDomains: @{\n\
        @"' + PARAM_SERVER_PINNED_DOMAIN + '" : @{\n\
            kTSKIncludeSubdomains: @YES,\n\
            kTSKEnforcePinning: @YES,\n\
            kTSKDisableDefaultReportUri: @YES,\n\
            kTSKPublicKeyHashes : @[\n\
              @"' + pubkey256hashb64 + '",\n\
              @"' + throwAwayCaPubkeyHash + '",\n\
            ],\n\
        },\n\
    }};\n\
  [TrustKit initSharedInstanceWithConfiguration:trustKitConfig];\n\n\
  self.moduleName = @"main";'
      );

      if ( ! AppDelegateModifiedContents.includes('kTSKPinnedDomains: @{')) {
        console.error('Error: We expected the patch to be applied or to be already present (1).');
        process.exit(1);
      }
  
      AppDelegateModifiedContents = AppDelegateModifiedContents.replace('#import <React/RCTLinkingManager.h>','\
#import <React/RCTLinkingManager.h>\n\
#import <TrustKit/TrustKit.h>'
      );

      if ( ! AppDelegateModifiedContents.includes('#import <TrustKit/TrustKit.h>')) {
        console.error('Error: We expected the patch to be applied or to be already present (2).');
        process.exit(1);
      }

      fs.writeFileSync('ios/ppclient/AppDelegate.mm', AppDelegateModifiedContents, {encoding: 'utf8'});
  
      //console.warn('AppDelegateModifiedContents:');
      //console.warn(AppDelegateModifiedContents);
  
    }

//*/
    return config;
  });
};

module.exports = createRunOncePlugin(
  withInfoPlistHttpConfigurations,
  'withInfoPlistHttpConfigurations',
  '1.0.0'
);

