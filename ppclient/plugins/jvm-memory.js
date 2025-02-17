const { createRunOncePlugin, withNothing } = require('@expo/config-plugins');


// ToDo: Migrate this plugin to a createRunOncePlugin,withAndroidManifest plugin
 
const withJvmMemory = config => {
  // Do not use console.log, as gradle takes it as the return config value
  console.warn('withJvmMemory started');
 
  try {
    var fs = require('fs');
    var path = require('path');

    var myfilepath = path.parse(__dirname).dir+'/android/gradle.properties';
  
    var text = fs.readFileSync(myfilepath, {encoding: 'utf8', flag: 'r'});
   
    text = text.toString().replace(/org.gradle.jvmargs=-Xmx2048m -XX:MaxMetaspaceSize=512m/, 'org.gradle.jvmargs=-Xmx4096m -XX:MaxMetaspaceSize=4096m');

    fs.writeFileSync(myfilepath, text, {encoding: 'utf8', flag: 'w+'});

    console.warn('withJvmMemory success');    

  } catch (err) {
    console.warn('Error: '+err.message);
  }

  return config;
  
};

module.exports = createRunOncePlugin(
  withJvmMemory,
  'withJvmMemory',
  '1.0.0'
);

