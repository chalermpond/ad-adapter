import {
    Controller,
    Get,
    HttpException,
    HttpStatus,
    Query,
    Req,
} from '@nestjs/common'
import { AppService } from './app.service'
import { map } from 'rxjs/operators'
import * as Config from 'config'

@Controller()
export class AppController {
    private readonly _config: any

    constructor(
        private readonly appService: AppService,
    ) {
        this._config = Config.util.toObject()
    }

    @Get('/checkUser')
    login(
        @Query('user') user: string,
        @Req() req: any,
    ) {
        const xToken = req.headers['x-token']
        if (xToken !== this._config.auth.secret) {
            throw new HttpException('Unauthorized',
                HttpStatus.UNAUTHORIZED)
        }
        return this.appService.login(user).pipe(
            map(token => ({token})),
        )
    }

    @Get('/validate')
    validate(
        @Req() req: any,
    ) {
        const token = req.headers['x-ad-auth']
        return this.appService.validate(token).pipe(
            map(result => ({result})),
        )
    }
}
