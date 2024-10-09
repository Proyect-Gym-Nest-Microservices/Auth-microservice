import { HttpStatus, Inject, Injectable, Logger, OnModuleInit } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { ClientProxy, RpcException } from "@nestjs/microservices";
import { PrismaClient } from "@prisma/client";
import { JwtPayload } from "./interfaces/jwt-payload.interface";
import { envs, NATS_SERVICE } from "src/config";
import { RegisterUserDto } from "./dto/register-user.dto";
import * as bcrypt from 'bcrypt'
import { LoginUserDto } from "./dto/login-user.dto";
import { firstValueFrom, timeout, TimeoutError } from "rxjs";
import { ChangePasswordDto } from "./dto/change-password.dto";
import { ForgotPasswordDto } from "./dto/forgot-password.dto";
import { ResetPasswordDto } from './dto/reset-password.dto';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {

    private readonly logger = new Logger('Auth-Service');

    constructor(
        @Inject(NATS_SERVICE) private readonly client: ClientProxy,
        private readonly jwtService: JwtService
    ) {
        super()
    }
    onModuleInit() {
        this.$connect()
        this.logger.log('MongoDb connected')
    }

    private async generateTokens(payload: JwtPayload) {
        const accessToken = this.generateAccessToken(payload);
        const refreshToken = this.generateRefreshToken(payload);
        await this.saveRefreshToken(refreshToken, payload.id);
        return { accessToken, refreshToken };
    }
    
    private generateAccessToken(payload: JwtPayload): string {
        return this.jwtService.sign(payload, {
            expiresIn: '20m',
            secret: envs.JWT_SECRET_ACCESS
        });
    }
    private generateResetToken(userId: string): string {
        return this.jwtService.sign({id:userId}, {
            expiresIn: '15m',
            secret: envs.JWT_SECRET_RESET_PASSWORD
        });
    }
    
    private generateRefreshToken(payload: JwtPayload): string {
        return this.jwtService.sign(payload, {
            expiresIn: '7d',
            secret: envs.JWT_SECRET_REFRESH
        });
    }
    
    private async saveRefreshToken(refreshToken: string, userId: string) {
        await this.refreshToken.create({
            data: {
                token: refreshToken,
                userId,
                expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
            },
        });
    }
    
    private async revokeRefreshToken(id: string) {
        await this.refreshToken.update({
            where: { id },
            data: { isRevoked: true },
        });
    }
    
    private async revokeAllUserTokens(userId: string) {
        await this.refreshToken.updateMany({
            where: { userId },
            data: { isRevoked: true },
        });
    }
    private handleError(error: any, defaultMessage: string) {
        if (error instanceof RpcException) {
            throw error;
        }
        if (error instanceof TimeoutError) {
            throw new RpcException({
                status: HttpStatus.GATEWAY_TIMEOUT,
                message: 'Operation timed out',
            });
        } 
        throw new RpcException({
            status: HttpStatus.INTERNAL_SERVER_ERROR,
            message: error.message || defaultMessage,
        });
    }

    async verifyAccessToken(token: string) {
        try {
            const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
                secret: envs.JWT_SECRET_ACCESS
            })
            const { id, roles } = user
            return { user: { id, roles } }
        } catch (error) {
            throw new RpcException({
                status: HttpStatus.UNAUTHORIZED,
                message: 'Invalid Token'
            })
        }
    }

    async refreshAccessToken(refreshToken: string) {
        try {
            const storedRefreshToken = await this.refreshToken.findUnique({
                where: { token: refreshToken },
            });

            if (!storedRefreshToken) {
                throw new RpcException({
                    status: HttpStatus.UNAUTHORIZED,
                    message: 'Refresh token not found'
                });
            };
            
            if (new Date() > storedRefreshToken.expiresAt) {
                await this.revokeRefreshToken(storedRefreshToken.id)
                throw new RpcException({
                    status: HttpStatus.UNAUTHORIZED,
                    message: 'Refresh token has expired.  Please log in again.'
                });
            }
            
            if (storedRefreshToken.isRevoked) {
                throw new RpcException({
                    status: HttpStatus.UNAUTHORIZED,
                    message: 'Refresh token has been revoked'
                });
            }

            const payload = this.jwtService.verify(refreshToken, {
                secret: envs.JWT_SECRET_REFRESH
            });


            if (payload.id !== storedRefreshToken.userId) {
                await this.revokeRefreshToken(storedRefreshToken.id)
                throw new RpcException({
                    status: HttpStatus.UNAUTHORIZED,
                    message: 'Token mismatch. Please log in again.'
                });
            }
            const { id, roles } = payload
            const newAccessToken = this.generateAccessToken({ id, roles });
            return { accessToken: newAccessToken, refreshToken };

        } catch (error) {
            this.handleError(error,'An error occurred during token refresh')
        }
    }


    async registerUser(registerUserDto: RegisterUserDto) {
        const { name, email, password } = registerUserDto;
        try {
            const hashedPassword = await bcrypt.hash(password, 10);

            const newUser = await firstValueFrom(
                this.client.send('create.user', {
                    email,
                    name,
                    password: hashedPassword
                }).pipe(timeout(5000))
            )
            const { roles, id } = newUser;
            const tokens = await this.generateTokens({ id, roles })
            return {user: { id, roles },...tokens}

        } catch (error) {
            this.handleError(error, 'Error while creating user');
        }

    }

    async loginUser(loginUserDto: LoginUserDto) {
        const { email, password } = loginUserDto
        try {
            const user = await firstValueFrom(
                this.client.send('find.user.by.email', email).pipe(timeout(5000))
            )
            const isPasswordValid = await bcrypt.compare(password, user.password);
            if (!isPasswordValid) {
                throw new RpcException({
                    status: HttpStatus.BAD_REQUEST,
                    message: 'Invalid credentials'
                })
            }
            const { id, roles } = user
            const tokens = await this.generateTokens({ id, roles })

            return {user: { id, roles },...tokens}

        } catch (error) {
            this.handleError(error,'Invalid Credentials')
        }

    }
    async changePassword(changePasswordDto:ChangePasswordDto) {
        const { userId, currentPassword, newPassword, confirmNewPassword } = changePasswordDto;
        try {

            if (newPassword !== confirmNewPassword) {
                throw new RpcException({
                    status: HttpStatus.BAD_REQUEST,
                    message: 'New password and confirmation do not match'
                });
            }

            const user = await firstValueFrom(
                this.client.send('find.user.by.id', userId).pipe(timeout(5000))
            );
            const isPasswordValid = await bcrypt.compare(currentPassword, user.password);

            if (!isPasswordValid) {
                throw new RpcException({
                    status: HttpStatus.BAD_REQUEST,
                    message: 'Invalid current password'
                });
            }

            const hashedNewPassword = await bcrypt.hash(newPassword, 10);

            const updatedUser = await firstValueFrom(
                this.client.send('update.user',{id:userId,password: hashedNewPassword}).pipe(timeout(5000))
            )

            await this.revokeAllUserTokens(userId);
            return {
                message: 'Password changed successfully',
                ...updatedUser
            };
        } catch (error) {
            this.handleError(error, 'Error changing password');
        }
    }

    async forgotPassword(forgotPassworddto: ForgotPasswordDto) {
        const { email } = forgotPassworddto;
        try {
            const user = await firstValueFrom(
                this.client.send('find.user.by.email', email).pipe(timeout(5000))
            );
            if (!user) {
                throw new RpcException({
                    status: HttpStatus.NOT_FOUND,
                    message: 'User not found'
                });
            }
    
            const resetToken = this.generateResetToken(user.id);
        
            await this.resetToken.create({
                data: {
                    token: resetToken,
                    userId: user.id,
                    expiresAt: new Date(Date.now() + 20 * 60 * 1000), // 20 min
                },
            });

            const emailService = await firstValueFrom(
                this.client.send('email.password.reset', {
                    email: user.email,
                    resetToken: resetToken
                }).pipe(timeout(5000))
            );
    
            return emailService;
        } catch (error) {
            this.handleError(error, 'Error processing forgot password request');
        }
    }

    async resetPassword(resetPasswordDto:ResetPasswordDto) {
        const { token, password: newPassword } = resetPasswordDto;
        this.logger.error(resetPasswordDto)

        try {
            await this.jwtService.verifyAsync(token, {
                secret: envs.JWT_SECRET_RESET_PASSWORD
            });

            const resetToken = await this.resetToken.findUnique({
                where: { token }
            });

            if (!resetToken || resetToken.isUsed || resetToken.expiresAt < new Date()) {
                throw new RpcException({
                    status: HttpStatus.BAD_REQUEST,
                    message: 'Invalid or expired reset token'
                });
            }

            const hashedPassword = await bcrypt.hash(newPassword, 10);


            await this.$transaction(async (prismaTransaction) => {
                // Actualizar el usuario a través del microservicio
                await firstValueFrom(
                    this.client.send('update.user', {
                        id: resetToken.userId,
                        password: hashedPassword
                    }).pipe(timeout(5000))
                );

                // Actualizar el token de restablecimiento
                await prismaTransaction.resetToken.update({
                    where: { id: resetToken.id },
                    data: { isUsed: true }
                });
            });
            // Revocar todos los tokens del usuario
            await this.revokeAllUserTokens(resetToken.userId);

            return {
                message: 'Password reset successfully'
            };
        } catch (error) {
            this.logger.error(error)
            this.handleError(error, 'Error resetting password');
        }
        
    }

}
