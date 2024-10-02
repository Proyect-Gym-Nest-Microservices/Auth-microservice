import { Role } from '@prisma/client';
//import { RolesList } from '../enum/roles.enum';


export interface JwtPayload{
    id: string;
    email: string;
    name: string;
    roles?: Role[]
}