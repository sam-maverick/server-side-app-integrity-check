import { Schema, model } from 'mongoose';

const PictureSchema = new Schema({
    pictureId: {type: String},  // This identifier is known to both sender and recipient, within the ppclient only. The messaging app does not know this ID
    pictureIdSenderPrivate: {type: String},  // This identifier is only known to the sender, within the ppclient only. The messaging app does not know this ID
    reported: {type: Boolean},
    unsent: {type: Boolean},
    viewed: {type: Boolean},
});


const PicturesModel = model('Pictures', PictureSchema);
export default PicturesModel;
