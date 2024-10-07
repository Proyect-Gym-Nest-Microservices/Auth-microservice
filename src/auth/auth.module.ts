import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { envs } from 'src/config';
import { NatsModule } from 'src/transports/nats.module';

@Module({
  controllers: [AuthController],
  providers: [AuthService],
  imports: [
    JwtModule.register({
      global: true, 
      //secret: envs.JWT_SECRET,
      //signOptions:{expiresIn:'2h'}
    }),
    NatsModule
  ]
})
export class AuthModule {}
