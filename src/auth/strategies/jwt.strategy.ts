import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../../users/users.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor(
        config: ConfigService,
        private usersService: UsersService,
    ) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: config.get<string>('JWT_SECRET') || 'change_me_please',
        });
    }

    async validate(payload: any) {
        const userId = payload._id || payload.sub || payload.id;
        if (!userId) {
            throw new UnauthorizedException('Invalid token payload');
        }

        try {
            const user = await this.usersService.findById(userId);

            if (!user) {
                throw new UnauthorizedException('User not found');
            }

            if (user.token !== payload.token) {
                throw new UnauthorizedException('Token mismatch');
            }
            return user;
        } catch (error) {
            throw new UnauthorizedException('Invalid token or user not found');
        }
    }
}
