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

    async login(user: LoginDto) {

        const UserData = await this.usersService.findByEmail(user.email);
        if (!UserData) throw new UnauthorizedException("User not found");

        const match = await bcrypt.compare(user.password, UserData.password);
        if (!match) throw new UnauthorizedException("Invalid credentials");

        const payload = { email: user.email, userType: UserData.userType, name: UserData.name };
        return {
            data: UserData,
            access_token: await this.jwt.signAsync(payload),
        };
    }

    async register(data: CreateUserDto) {
        const user = await this.userModel.create(data);

        const payload = { email: user.email, sub: (user as any)._id?.toString?.() ?? user.id };
        return {
            data: user,
            access_token: await this.jwt.signAsync(payload),
        };
    }
}