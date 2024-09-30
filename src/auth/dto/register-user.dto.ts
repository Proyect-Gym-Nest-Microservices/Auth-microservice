import { IsBoolean, IsEmail, IsOptional, IsString, IsStrongPassword } from "class-validator"

export class RegisterUserDto {

    @IsString()
    name:string

    @IsString()
    @IsEmail()
    email: string

    @IsString()
    @IsStrongPassword()
    password: string

    @IsBoolean()
    @IsOptional()
    isActive?: boolean = true;

    @IsString()
    @IsOptional()
    avatarUrl?: string;

    

}