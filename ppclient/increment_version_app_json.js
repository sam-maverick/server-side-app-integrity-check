#!/usr/bin/env node
require('shelljs/global');

const replaceInFile = (myfilepath, mypattern, mynewtext) => {
  try {
    echo('replaceOnceInFile started');    
    var fs = require('fs');
    var path = require('path');

    var text = fs.readFileSync(myfilepath, {encoding: 'utf8', flag: 'r'});
   
    echo('Previous text: '+text);
    text = text.toString().replace(mypattern, mynewtext);
    echo('Modified text: '+text);

    fs.writeFileSync(myfilepath, text, {encoding: 'utf8', flag: 'w+'});

    echo('replaceOnceInFile done');    

  } catch (err) {
    echo('replaceInFile() error: '+err.message);
  }

}



module.exports = function (level) { 

  echo('increment_version_app_json.js: incrementing level: '+level);

  if (level === 'patch') {
  
      replaceInFile(
          './app.json', 
          /    "version": "([0-9]+).([0-9]+).([0-9]+)",/g,
          function (match, v1, v2, v3) {
            return "    \"version\": \"" + v1 + "." + v2 + "." + (Number(v3)+1) + "\","
          }
      );
      //sed -r 's/\s\s\s\s"version": "([0-9]+).([0-9]+).([0-9]+)",/echo -n "    \\"version\\": \\"\1.\2.$((\3+1))\\","/ge' app.json > app.json.tmp
  }
  
  if (level === 'minor') {
  
      replaceInFile(
          './app.json', 
          /    "version": "([0-9]+).([0-9]+).([0-9]+)",/g,
          function (match, v1, v2, v3) {
            return "    \"version\": \"" + v1 + "." + (Number(v2)+1) + "." + v3 + "\","
          }
      );
      //sed -r 's/\s\s\s\s"version": "([0-9]+).([0-9]+).([0-9]+)",/echo -n "    \\"version\\": \\"\1.$((\2+1)).\3\\","/ge' app.json > app.json.tmp
  }
  
  if (level === 'major') {
  
      replaceInFile(
          './app.json', 
          /    "version": "([0-9]+).([0-9]+).([0-9]+)",/g,
          function (match, v1, v2, v3) {
            return "    \"version\": \"" + (Number(v1)+1) + "." + v2 + "." + v3 + "\","
          }
      );
      //sed -r 's/\s\s\s\s"version": "([0-9]+).([0-9]+).([0-9]+)",/echo -n "    \\"version\\": \\"$((\1+1)).\2.\3\\","/ge' app.json > app.json.tmp
  }  

}
