import {
    HttpException,
    HttpStatus,
    Injectable,
} from '@nestjs/common'
import * as AD from 'ad'
import {
    from,
    Observable,
    of,
} from 'rxjs'
import {
    map,
    tap,
} from 'rxjs/operators'
import * as Config from 'config'
import { JwtService } from './auth.service'

@Injectable()
export class AppService {
    private readonly _ad
    private readonly _config

    constructor(
        private readonly _jwt: JwtService,
    ) {
        this._config = Config.util.toObject()
        this._ad = new AD({
            url: `ldaps://${this._config.auth.host}`,
            user: this._config.auth.user,
            pass: this._config.auth.pass,
        })
    }

    public login(user: string) {
        const userScope = this._ad.user(user)
        return from(userScope.get()).pipe(
            tap((data: any) => {
                if (data.cn === undefined) {
                    throw new HttpException(`User not found`,
                        HttpStatus.NOT_FOUND)
                }
            }),
            map(() => ({success: true})),
            map((payload) => this._jwt.generateToken(payload)),
        )
    }

    public validate(token: string): Observable<boolean> {
        return of(this._jwt.verifyToken(token)).pipe(
            map(result => !!result),
        )
    }
}
