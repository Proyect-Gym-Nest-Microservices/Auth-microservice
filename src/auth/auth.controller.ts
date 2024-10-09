import { Controller } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import { RegisterUserDto } from './dto/register-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';


@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @MessagePattern('auth.register.user')
  registerUser(@Payload() registerUserDto: RegisterUserDto) {
    console.log({registerUserDto})
  
    return this.authService.registerUser(registerUserDto);
  }
  @MessagePattern('auth.login.user')
  loginUser(@Payload() loginUserDto:LoginUserDto) {
    return this.authService.loginUser(loginUserDto);  
  }
  
  @MessagePattern('auth.verify.token')
  verifyToken(@Payload() token: string) {
    return this.authService.verifyAccessToken(token);
  }

  @MessagePattern('auth.refresh.access.token')
  refreshAccessToken(@Payload() refreshToken:string) {
    return this.authService.refreshAccessToken(refreshToken);
  }

  @MessagePattern('auth.change.password')
  changePassword(@Payload() changePasswordDto: ChangePasswordDto  ) {
    return this.authService.changePassword(changePasswordDto)
  }

  @MessagePattern('auth.forgot.password')
  forgotPassword(@Payload() forgotPassworddto:ForgotPasswordDto ) {
    return this.authService.forgotPassword(forgotPassworddto)
  }
}
