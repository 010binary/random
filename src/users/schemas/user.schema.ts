import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

export type UserDocument = HydratedDocument<User>;

@Schema({ timestamps: true })
export class User {
    @Prop({ required: true, unique: true, lowercase: true, trim: true })
    email: string;

    @Prop({ required: true })
    password: string;

    @Prop({ required: true })
    name: string;

    @Prop({ enum: ['user', 'creator', 'admin'], default: 'user' })
    userType: string;

    @Prop({ trim: true })
    ProfilePicture?: string;

    @Prop()
    token?: string;
}

export const UserSchema = SchemaFactory.createForClass(User);

UserSchema.set('toJSON', {
    versionKey: false,
    transform: (_doc: any, ret: any) => {
        delete ret.password;
        return ret;
    },
});
