import { IsEmail, IsEnum, IsOptional, IsString, MinLength } from 'class-validator';


enum UserType {
    USER = 'user',
    CREATOR = 'creator',
    ADMIN = 'admin',
}


export class CreateUserDto {
    @IsEmail()
    email: string;

    @IsString()
    @MinLength(6)
    password: string;

    @IsString()
    @MinLength(6)
    confirmPassword: string;

    @IsEnum(UserType)
    userType: UserType;
}
