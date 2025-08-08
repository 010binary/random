import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from './schemas/user.schema';
import { CreateUserDto } from './dto/create-user.dto';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class UsersService {
    constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) { }

    async create(dto: CreateUserDto): Promise<User> {
        const exists = await this.userModel.exists({ email: dto.email.toLowerCase() });
        if (exists) throw new ConflictException('Email already in use');

        const hash = await bcrypt.hash(dto.password, 10);
        const created = new this.userModel({ ...dto, email: dto.email.toLowerCase(), password: hash });
        return created.save();
    }

    async findByEmail(email: string): Promise<User | null> {
        return this.userModel.findOne({ email: email.toLowerCase() }).exec();
    }

    async findById(id: string): Promise<User> {
        const user = await this.userModel.findById(id).exec();
        if (!user) throw new NotFoundException('User not found');
        return user;
    }
}
