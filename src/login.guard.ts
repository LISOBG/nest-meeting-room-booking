import { CanActivate, ExecutionContext, Inject, Injectable } from '@nestjs/common';
import { Observable } from 'rxjs';
import { Permission } from './user/entities/permission.entity';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';


interface JwtUserData {
  userId: number;
  username: string;
  roles: string[];
  permissions: Permission[]
}

declare module 'express' {
  interface Request {
    user: JwtUserData
  }
}
@Injectable()
export class LoginGuard implements CanActivate {

  @Inject()
  private reflector: Reflector

  @Inject()
  private jwtService: JwtService

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {

    const request: Request = context.switchToHttp().getRequest();

    const requireLogin = this.reflector.getAllAndOverride('require-login', [
      context.getClass(),
      context.getHandler()
    ])

    if (!requireLogin) {
      return true
    }
    return true;
  }
}
