import { RolesList } from '../enum/roles.enum';


export interface JwtPayload{
    id: string;
    email: string;
    name: string;
}