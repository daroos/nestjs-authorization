import { BadRequestException, Injectable, Req, Res, UnauthorizedException } from '@nestjs/common';
import { UserService } from '../user/user.service';
import { JwtService } from '@nestjs/jwt';
import { User } from '../user.entity';

@Injectable()
export class AuthService {
    constructor(
        private readonly userService: UserService,
        private readonly jwtService: JwtService,
    ) {}

    private async validate(userData: User): Promise<User> {
        return await this.userService.findByEmailAndPassword(userData.email, userData.password);
    }

    public async login(user: User): Promise<any | { status: number }> {
        const userData = await this.validate(user);

        if (!userData) {
            throw new UnauthorizedException('No such user');
        }

        let payload = `${userData.name}${userData.id}`;
        const accessToken = this.jwtService.sign(payload);

        return {
            expires_in: 3600,
            access_token: accessToken,
            user_id: payload,
            status: 200,
        };

    }

    public async register(user: User): Promise<any> {
        return this.userService.create(user);
    }
}
