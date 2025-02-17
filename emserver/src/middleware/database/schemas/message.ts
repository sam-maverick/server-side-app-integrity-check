import { Schema, model } from 'mongoose';

const MessageSchema = new Schema({  // These are the queued messages of the recipient, pending from retrieval
    sender: {type: String},
    recipient: {type: String},
    message: {type: Array},
});

const MessagesModel = model('Messages', MessageSchema);
export default MessagesModel;
