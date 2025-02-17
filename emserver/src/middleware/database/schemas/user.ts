import { Schema, model } from 'mongoose';

const UserSchema = new Schema({  // These are the user accounts
    username: {type: String},
    cookie: {type: String},
});

const UsersModel = model('Users', UserSchema);
export default UsersModel;
