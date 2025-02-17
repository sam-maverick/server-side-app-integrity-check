const { promisify } = require('util');
const exec = promisify(require('child_process').exec);
const fs = require('fs');

const { createRunOncePlugin, withInfoPlist } = require('expo/config-plugins');



const withInfoPlistPostPodinstall = (config, id) => {
  return withInfoPlist(config, async(config) => {

    
  console.log('post_podinstall.ts started');






  console.log('Pod install');

  // We need to pod-install to generate the files we want to modify.
  // Caveat: pod-install is not idempotent and we cannot control the order of execution of plugins.
  // Therefore, we must concentrate all post pod-install modifications here
  await exec('cd ios ; pod install');



  console.log('Modifications to private / RCTDefines.h');

  const pathfile1 = 'ios/Pods/Headers/Private/React-Core/React/RCTDefines.h';
  await exec('chmod u+w '+pathfile1);

  let RctPortfileOriginalContents = fs.readFileSync(pathfile1, {encoding: 'utf8'});
  let RctPortfileModifiedContents;

  if ( ! RctPortfileOriginalContents.includes('//return TSKTrustEvaluationFailedInvalidCertificateChain;')) {
    RctPortfileModifiedContents = RctPortfileOriginalContents.replace(
      /#define RCT_METRO_PORT 8081/, 
      '#define RCT_METRO_PORT 8083'
    );
  }

    if ( ! RctPortfileModifiedContents.includes('#define RCT_METRO_PORT 8083')) {
      console.error('Error with patching');
      process.exit(1);
    }

    fs.writeFileSync(pathfile1, RctPortfileModifiedContents, {encoding: 'utf8'});



    console.log('Modifications to public / RCTDefines.h');

    const pathfile2 = 'ios/Pods/Headers/Public/React-Core/React/RCTDefines.h';
    await exec('chmod u+w '+pathfile2);
  
    RctPortfileOriginalContents = fs.readFileSync(pathfile2, {encoding: 'utf8'});
  
    if ( ! RctPortfileOriginalContents.includes('//return TSKTrustEvaluationFailedInvalidCertificateChain;')) {
      RctPortfileModifiedContents = RctPortfileOriginalContents.replace(
        /#define RCT_METRO_PORT 8081/, 
        '#define RCT_METRO_PORT 8083'
      );
    }
  
      if ( ! RctPortfileModifiedContents.includes('#define RCT_METRO_PORT 8083')) {
        console.error('Error with patching');
        process.exit(1);
      }
  
      fs.writeFileSync(pathfile2, RctPortfileModifiedContents, {encoding: 'utf8'});
  




  return config;
});
};

module.exports = createRunOncePlugin(
withInfoPlistPostPodinstall,
'withInfoPlistPostPodinstall',
'1.0.0'
);
