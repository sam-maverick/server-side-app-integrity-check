import { Schema, model } from 'mongoose';

const DeviceSchema = new Schema({
    nonces: {
        android_classic: {
            nonce: {type: String},
            timestamp: {type: Number},
            consumed: {type: Boolean},
        },
        android_standard: {
            nonce: {type: String},
            timestamp: {type: Number},
            consumed: {type: Boolean},
        },
        ios_attestation: {
            nonce: {type: String},
            timestamp: {type: Number},
            consumed: {type: Boolean},
        },
        ios_assertion: {
            nonce: {type: String},
            timestamp: {type: Number},
            consumed: {type: Boolean},
        },
    },
    cookie: {type: String},
    timestamp: {type: Number},
    iosIsDevelopment: {type: Boolean},
    iosPublicKeyPEM: {type: String},
    iosReceipt: {type: String},
    iosSignCount: {type: String},
});
// timestamp is in milliseconds

const DevicesModel = model('Devices', DeviceSchema);
export default DevicesModel;
