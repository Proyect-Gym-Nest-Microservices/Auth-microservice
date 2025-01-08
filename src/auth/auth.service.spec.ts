import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { JwtService } from '@nestjs/jwt';
import { ClientProxy, RpcException } from '@nestjs/microservices';
import { NATS_SERVICE } from '../config/services.config';
import { RegisterUserDto } from './dto/register-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import * as bcrypt from 'bcrypt';
import { of, throwError } from 'rxjs';

// Mocks
const jwtServiceMock = {
  sign: jest.fn(),
  verify: jest.fn(),
  verifyAsync: jest.fn()
};

const clientProxyMock = {
  send: jest.fn()
};

const prismaServiceMock = {
  refreshToken: {
    create: jest.fn(),
    findUnique: jest.fn(),
    update: jest.fn(),
    updateMany: jest.fn()
  },
  resetToken: {
    create: jest.fn(),
    findUnique: jest.fn(),
    update: jest.fn()
  },
  $connect: jest.fn(),
  $transaction: jest.fn(callback => callback(prismaServiceMock))
};

describe('AuthService', () => {
  let service: AuthService;
  let jwtService: JwtService;
  let clientProxy: ClientProxy;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: JwtService,
          useValue: jwtServiceMock
        },
        {
          provide: NATS_SERVICE,
          useValue: clientProxyMock
        }
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    jwtService = module.get<JwtService>(JwtService);
    clientProxy = module.get<ClientProxy>(NATS_SERVICE);

    // Asignar los mocks de Prisma
    Object.assign(service, prismaServiceMock);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('registerUser', () => {
    const registerDto: RegisterUserDto = {
      name: 'Test User',
      email: 'test@test.com',
      password: 'StrongPass123!'
    };

    it('should register a new user successfully', async () => {
      const hashedPassword = 'hashedPassword123';
      const userId = '1';
      const userRoles = ['USER'];

      jest.spyOn(bcrypt, 'hash').mockResolvedValue(hashedPassword as never);
      
      clientProxyMock.send.mockReturnValueOnce(of({
        id: userId,
        roles: userRoles
      }));

      jwtServiceMock.sign
        .mockReturnValueOnce('access-token')
        .mockReturnValueOnce('refresh-token');

      prismaServiceMock.refreshToken.create.mockResolvedValue({});

      const result = await service.registerUser(registerDto);

      expect(result).toHaveProperty('accessToken');
      expect(result).toHaveProperty('refreshToken');
      expect(result.user).toEqual({
        id: userId,
        roles: userRoles
      });
    });

    it('should throw an error if user creation fails', async () => {
      clientProxyMock.send.mockReturnValueOnce(
        throwError(() => new Error('Database error'))
      );

      await expect(service.registerUser(registerDto))
        .rejects
        .toThrow(RpcException);
    });
  });

  describe('loginUser', () => {
    const loginDto: LoginUserDto = {
      email: 'test@test.com',
      password: 'StrongPass123!'
    };

    it('should login user successfully', async () => {
      const userId = '1';
      const userRoles = ['USER'];
      const hashedPassword = await bcrypt.hash(loginDto.password, 10);

      clientProxyMock.send.mockReturnValueOnce(of({
        id: userId,
        roles: userRoles,
        password: hashedPassword
      }));

      jwtServiceMock.sign
        .mockReturnValueOnce('access-token')
        .mockReturnValueOnce('refresh-token');

      prismaServiceMock.refreshToken.create.mockResolvedValue({});

      const result = await service.loginUser(loginDto);

      expect(result).toHaveProperty('accessToken');
      expect(result).toHaveProperty('refreshToken');
      expect(result.user).toEqual({
        id: userId,
        roles: userRoles
      });
    });

    it('should throw an error for invalid credentials', async () => {
      const hashedPassword = await bcrypt.hash('differentPassword', 10);

      clientProxyMock.send.mockReturnValueOnce(of({
        password: hashedPassword
      }));

      await expect(service.loginUser(loginDto))
        .rejects
        .toThrow(RpcException);
    });
  });

  describe('changePassword', () => {
    const changePasswordDto: ChangePasswordDto = {
      userId: '1',
      currentPassword: 'CurrentPass123!',
      newPassword: 'NewPass123!',
      confirmNewPassword: 'NewPass123!'
    };

    it('should change password successfully', async () => {
      const hashedOldPassword = await bcrypt.hash(changePasswordDto.currentPassword, 10);

      clientProxyMock.send.mockReturnValueOnce(of({
        id: changePasswordDto.userId,
        password: hashedOldPassword
      }));

      clientProxyMock.send.mockReturnValueOnce(of({
        id: changePasswordDto.userId,
        updated: true
      }));

      const result = await service.changePassword(changePasswordDto);

      expect(result).toHaveProperty('message', 'Password changed successfully');
    });

    it('should throw error if passwords do not match', async () => {
      const invalidDto = {
        ...changePasswordDto,
        confirmNewPassword: 'DifferentPass123!'
      };

      await expect(service.changePassword(invalidDto))
        .rejects
        .toThrow(RpcException);
    });
  });

  describe('forgotPassword', () => {
    const forgotPasswordDto: ForgotPasswordDto = {
      email: 'test@test.com'
    };

    it('should process forgot password request successfully', async () => {
      const userId = '1';

      clientProxyMock.send.mockReturnValueOnce(of({
        id: userId,
        email: forgotPasswordDto.email
      }));

      jwtServiceMock.sign.mockReturnValue('reset-token');

      clientProxyMock.send.mockReturnValueOnce(of({
        success: true,
        message: 'Reset email sent'
      }));

      const result = await service.forgotPassword(forgotPasswordDto);

      expect(result).toHaveProperty('success', true);
      expect(prismaServiceMock.resetToken.create).toHaveBeenCalled();
    });

    it('should throw error if user not found', async () => {
      clientProxyMock.send.mockReturnValueOnce(of(null));

      await expect(service.forgotPassword(forgotPasswordDto))
        .rejects
        .toThrow(RpcException);
    });
  });

  describe('resetPassword', () => {
    const resetPasswordDto: ResetPasswordDto = {
      token: 'valid-reset-token',
      password: 'NewPass123!'
    };

    it('should reset password successfully', async () => {
      const userId = '1';

      jwtServiceMock.verifyAsync.mockResolvedValue({ id: userId });

      prismaServiceMock.resetToken.findUnique.mockResolvedValue({
        id: '1',
        userId,
        isUsed: false,
        expiresAt: new Date(Date.now() + 3600000)
      });

      clientProxyMock.send.mockReturnValueOnce(of({
        id: userId,
        updated: true
      }));

      const result = await service.resetPassword(resetPasswordDto);

      expect(result).toHaveProperty('message', 'Password reset successfully');
      expect(prismaServiceMock.resetToken.update).toHaveBeenCalled();
      expect(prismaServiceMock.refreshToken.updateMany).toHaveBeenCalled();
    });

    it('should throw error for expired token', async () => {
      jwtServiceMock.verifyAsync.mockResolvedValue({ id: '1' });

      prismaServiceMock.resetToken.findUnique.mockResolvedValue({
        id: '1',
        userId: '1',
        isUsed: false,
        expiresAt: new Date(Date.now() - 3600000)
      });

      await expect(service.resetPassword(resetPasswordDto))
        .rejects
        .toThrow(RpcException);
    });
  });

  describe('token verification', () => {
    const testToken = 'valid-token';
    const testPayload = {
      id: '1',
      roles: ['USER'],
      sub: 'subject',
      iat: 1234567890,
      exp: 9999999999
    };

    describe('verifyAccessToken', () => {
      it('should verify access token successfully', async () => {
        jwtServiceMock.verify.mockReturnValue(testPayload);

        const result = await service.verifyAccessToken(testToken);

        expect(result.user).toEqual({
          id: testPayload.id,
          roles: testPayload.roles
        });
      });

      it('should throw error for invalid access token', async () => {
        jwtServiceMock.verify.mockImplementation(() => {
          throw new Error('Invalid token');
        });

        await expect(service.verifyAccessToken(testToken))
          .rejects
          .toThrow(RpcException);
      });
    });

    describe('verifyRefreshToken', () => {
      it('should verify refresh token successfully', async () => {
        jwtServiceMock.verify.mockReturnValue(testPayload);

        const result = await service.verifyRefreshToken(testToken);

        expect(result.user).toEqual({
          id: testPayload.id,
          roles: testPayload.roles
        });
      });

      it('should throw error for invalid refresh token', async () => {
        jwtServiceMock.verify.mockImplementation(() => {
          throw new Error('Invalid token');
        });

        await expect(service.verifyRefreshToken(testToken))
          .rejects
          .toThrow(RpcException);
      });
    });
  });
});