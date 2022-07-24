import {
    Observable,
    of,
} from 'rxjs'
import { readFileSync } from 'fs'
import {
    HttpException,
    HttpStatus,
    Inject,
    Injectable,
} from '@nestjs/common'

import * as Config from 'config'

import {
    sign,
    verify,
    VerifyOptions,
} from 'jsonwebtoken'
import { tap } from 'rxjs/internal/operators/tap'
import { mergeMap } from 'rxjs/operators'

@Injectable()
export class JwtService {
    private readonly _signAlgorithm: string = 'RS256'
    private readonly _publicKey: Buffer
    private readonly _privateKey: Buffer
    private readonly _tokenTTL: string = '10m'
    private readonly _refreshTTL: string = '2h'
    private readonly _ignoreExpiration: boolean
    private readonly _config: any

    constructor() {
        this._config = Config.util.toObject()
        this._ignoreExpiration = !!this._config.auth.ignoreExpiration
        this._publicKey = readFileSync(this._config.auth.public)
        this._privateKey = readFileSync(this._config.auth.private)
    }

    public generateToken(payload: any): string {
        return sign(payload,
            this._privateKey,
            {
                algorithm: this._signAlgorithm,
                expiresIn: this._tokenTTL,
            })
    }

    public verifyToken(token: string): any {
        const verifyOpts: VerifyOptions = {
            algorithms: [this._signAlgorithm],
            ignoreExpiration: this._ignoreExpiration,
        }
        try {
            return verify(token, this._publicKey, verifyOpts)
        } catch (e) {
            return false
        }

    }

    public refreshToken(token: any): Observable<any> {
        return of(this.verifyToken(token)).pipe(
            tap((result: any) => {
                console.log(result)
                if (!result) {
                    throw new HttpException(
                        'Invalid Token',
                        HttpStatus.BAD_REQUEST,
                    )
                }
            }),
            mergeMap((decoded: any) => {
                return this.generateToken(decoded)
            }),
        )
    }

}
