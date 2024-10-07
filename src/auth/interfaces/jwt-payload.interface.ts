//import { Role } from '@prisma/client';




export interface JwtPayload{
    id: string;
    //email: string;
    //name: string;
    roles?: string[]
}