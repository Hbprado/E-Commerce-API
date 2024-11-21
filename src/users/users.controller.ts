import { Controller, Post, Body, Get, Param, Patch, Delete, UseGuards, Req } from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { JwtGuard } from '../auth/jwt/jwt.guard';
import { Request } from 'express';
import { AuthService } from '../auth/auth.service';

@Controller('users')
export class UsersController {
    constructor(
        private readonly usersService: UsersService,
        private readonly authService: AuthService,
    ) { }

    @Post('register')
    async register(@Body() createUserDto: CreateUserDto) {
        return this.usersService.create(createUserDto);
    }

    @Post('login')
    async login(@Body() body: { email: string; password: string }) {
        return this.authService.login(body.email, body.password);
    }

    @UseGuards(JwtGuard)
    @Get('profile')
    async getProfile(@Req() req: Request) {
        return req.user;
    }

    @UseGuards(JwtGuard)
    @Patch('profile')
    async updateProfile(@Req() req: Request, @Body() updateUserDto: UpdateUserDto) {
        const user = req.user;
        await this.usersService.update(user.id, updateUserDto);
        return this.usersService.findOneByEmail(user.email);
    }

    @UseGuards(JwtGuard)
    @Delete('profile')
    async deleteProfile(@Req() req: Request) {
        const user = req.user;
        await this.usersService.remove(user.id);
    }
}