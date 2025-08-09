import { Body, Controller, Get, Param, Post, Req, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';

@Controller('user')
@UseGuards(JwtAuthGuard)
export class UsersController {
    constructor(private readonly usersService: UsersService) { }

    @Post()
    create(@Body() dto: CreateUserDto) {
        return this.usersService.create(dto);
    }

    @Get(':id')
    get(@Param('id') id: string) {
        return this.usersService.findById(id);
    }

    @Get('me')
    getProfile(@Req() req: any) {
        const x = ""
        return {};
    }
}
