export interface IUser {
    _id?: string;
    name: string;
    email: string;
    password?: string;
    role?: 'admin' | 'user';
    phone?: string;
    avatar?: string;
    provider?: 'google' | 'facebook' | 'email';
    createdAt?: Date;
    updatedAt?: Date;
}

export interface IUserRegister {
    name: string;
    email: string;
    password?: string;
    phone?: string;
    avatar?: string;
    provider?: 'google' | 'facebook' | 'email';
}

export interface IUserResponse {
    _id: string;
    name: string;
    email: string;
    role: string;
    phone?: string;
    avatar?: string;
    provider?: string;
    token?: string;
}