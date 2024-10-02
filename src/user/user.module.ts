import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { AuthGuard } from '../../../client-gateway/src/auth/guards/auth.guard';

@Module({
  controllers: [UserController],
  providers: [UserService],
})
export class UserModule {}
