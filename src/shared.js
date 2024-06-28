const maxTypeLength = 7;

import "dotenv/config";


/**
 * print a message to the console with the date and time
 * @param {String} type : Must be a string, with one of the following options: INFO, ERROR, DEBUG
 * @param {String} content
 * @param {String} loglevelofthisevent: Must be 0 (print log regardless of LOGGING_LEVEL parameter), 1 (informational and error) or 2 (debug)
 */
export function logEvent(type, content, loglevelofthisevent) {

  if ( ! ['INFO', 'ERROR', 'DEBUG'].includes(type))  return;

  let myLoggingLevel = 1;
  if (process.env.LOGGING_LEVEL) {
    myLoggingLevel = process.env.LOGGING_LEVEL;
  }

  if (loglevelofthisevent <= myLoggingLevel)  return;

  const date = new Date();
  const time = date.toLocaleTimeString();
  const dateString = date.toLocaleDateString();
  const placeholder = " ".repeat(Math.max(maxTypeLength - type.length, 0));
  console.log(`${dateString} ${time} [${type}] ${placeholder} ${content}`);
}

export function isInteger(value) {
  return /^\d+$/.test(value);
}

