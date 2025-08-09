import { Injectable, UnauthorizedException } from '@nestjs/common';
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

        const token = await this.jwt.signAsync({ email: dto.email, userType: UserData.userType, name: UserData.name })
        const user = await this.userModel.findOneAndUpdate({
            $where
            token
        })

        return {
            data: user,
        };
    }

    async register(dto: CreateUserDto) {
        const hashpassword = await bcrypt.hash(dto.password, 10);
        const payload = await this.jwt.signAsync({
            email: dto.email,
            userType: dto.userType,
            name: dto.name
        })

        const user = await this.userModel.create({
            ...dto,
            email: dto.email.toLowerCase(),
            password: hashpassword,
            token: payload
        });

        return {
            data: user,
        };
    }
}