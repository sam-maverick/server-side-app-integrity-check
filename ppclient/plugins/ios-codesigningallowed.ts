const { createRunOncePlugin, withInfoPlist } = require('expo/config-plugins');

// https://forums.developer.apple.com/forums/thread/656616


const withInfoPlistCodeSigningAllowed = (config, id) => {
  return withInfoPlist(config, async(config) => {

    console.warn('withInfoPlistCodeSigningAllowed started');
    
    const fs = require('fs');

    // Modifications to the Podfile

    let PodfileOriginalContents = fs.readFileSync('ios/Podfile', {encoding: 'utf8'});

      let PodfileModifiedContents = PodfileOriginalContents.replace(
        '    installer.target_installation_results.pod_target_installation_results\n\
      .each do |pod_name, target_installation_result|\n\
      target_installation_result.resource_bundle_targets.each do |resource_bundle_target|\n\
        resource_bundle_target.build_configurations.each do |config|\n\
          config.build_settings[\'CODE_SIGNING_ALLOWED\'] = \'NO\'\n\
        end\n\
      end\n\
    end\n\
', 
        '    installer.target_installation_results.pod_target_installation_results\n\
      .each do |pod_name, target_installation_result|\n\
      target_installation_result.resource_bundle_targets.each do |resource_bundle_target|\n\
        resource_bundle_target.build_configurations.each do |config|\n\
          config.build_settings[\'CODE_SIGNING_ALLOWED\'] = \'YES\'\n\
        end\n\
      end\n\
    end\n\
'
      );

      if ( ! PodfileModifiedContents.includes('config.build_settings[\'CODE_SIGNING_ALLOWED\'] = \'YES\'')) {
        console.error('Error: We expected the patch to be applied or to be already present (2).');
        process.exit(1);
      }
      
      fs.writeFileSync('ios/Podfile', PodfileModifiedContents, {encoding: 'utf8'});
  
      //console.warn('PodfileModifiedContents:');
      //console.warn(PodfileModifiedContents);


    return config;
  });
};

module.exports = createRunOncePlugin(
  withInfoPlistCodeSigningAllowed,
  'withInfoPlistCodeSigningAllowed',
  '1.0.0'
);

