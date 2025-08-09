import { BadRequestException, ConflictException, Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from 'src/users/schemas/user.schema';
import { LoginDto } from 'src/users/dto/login.dto';

@Injectable()
export class AuthService {
    constructor(
        private usersService: UsersService,
        private jwt: JwtService,
        @InjectModel(User.name)
        private userModel: Model<UserDocument>
    ) { }

    async validateUser(email: string, pass: string) {
        const user = await this.usersService.findByEmail(email);
        if (!user) return null;

        const match = await bcrypt.compare(pass, (user as any).password);
        if (!match) return null;

        return user;
    }

    async login(dto: LoginDto) {

        const UserData = await this.userModel.findOne({ email: dto.email.toLowerCase() }).exec();

        if (!UserData) throw new UnauthorizedException("User not found");

        const match = await bcrypt.compare(dto.password, UserData.password);
        if (!match) throw new UnauthorizedException("Invalid credentials");

        const token = await this.jwt.signAsync({
            email: dto.email,
            userType: UserData.userType,
            name: UserData.name,
            _id: UserData._id,
            sub: UserData._id  // Add standard JWT subject field
        })
        const user = await this.userModel.findOneAndUpdate({
            _id: UserData._id
        }, {
            token
        }, {
            new: true
        })

        return {
            data: user,
        };
    }

    async register(dto: CreateUserDto) {
        const exists = await this.userModel.exists({ email: dto.email.toLowerCase() });
        if (exists) throw new BadRequestException('Email already in use');

        const hashpassword = await bcrypt.hash(dto.password, 10);

        const user = await this.userModel.create({
            ...dto,
            email: dto.email.toLowerCase(),
            password: hashpassword,
        });
        const payload = await this.jwt.signAsync({
            email: dto.email,
            userType: dto.userType,
            name: dto.name,
            _id: user._id,
            sub: user._id  // Add standard JWT subject field
        })
        user.updateOne({
            token: payload
        });

        return {
            data: user,
        };
    }

    async logout(user: any) {
        await this.userModel.updateOne({ _id: user._id }, { $unset: { token: "" } });
    }
}