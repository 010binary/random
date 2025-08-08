import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
    constructor(private usersService: UsersService, private jwt: JwtService) { }

    async validateUser(email: string, pass: string) {
        const user = await this.usersService.findByEmail(email);
        if (!user) return null;

        const match = await bcrypt.compare(pass, (user as any).password);
        if (!match) return null;

        return user;
    }

    async login(user: any) {
        const payload = { email: user.email, sub: (user as any)._id?.toString?.() ?? user.id };
        return {
            access_token: await this.jwt.signAsync(payload),
        };
    }
}
