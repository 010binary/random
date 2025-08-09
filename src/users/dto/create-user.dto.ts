import { IsEmail, IsEnum, IsString, Matches, MinLength } from 'class-validator';


enum UserType {
    USER = 'user',
    CREATOR = 'creator',
    ADMIN = 'admin',
}


export class CreateUserDto {
    @IsEmail()
    email: string;

    @IsString()
    name: string;

    @IsString()
    @MinLength(6)
    password: string;

    @IsString()
    @MinLength(6)
    @Matches(/^/, { message: 'Passwords do not match' })
    confirmPassword: string;

    @IsEnum(UserType)
    userType: UserType;
}
