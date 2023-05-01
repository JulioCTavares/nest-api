import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { User } from '@prisma/client';
import { GetUser } from 'src/auth/decorator';
import { JwtGuard } from 'src/auth/guards';

@Controller('users')
export class UserController {

  @UseGuards(JwtGuard)
  @Get('me')
  getUserInfo(@GetUser() user: User) {

    return user;
  }
}
