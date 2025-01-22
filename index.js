const cors = require('cors')
const express = require('express')
const bodyParser = require('body-parser')

class SimpleServer {
    constructor(config) {
        if (typeof config !== 'object') {
            config = {}
        }

        if (Array.isArray(config.passwords)) {
            this.passwords = JSON.parse(JSON.stringify(config.passwords))
        } else {
            this.passwords = ['pass_general', 'pass_admin']
        }
        this.initFn = config.init
        this.rootFn = config.root
        this.getTable = config.GET
        this.postTable = config.POST
        this.log = config.log
        if (typeof config.port === 'number') {
            this.port = config.port
        } else {
            this.port = 80
        }

        this.permMap = {}
        this.passwords.forEach((x, n) => {
            this.permMap[x] = (n + 1)
        })

        this.app = express()
        this.app.use(cors())

        this.jsonParser = bodyParser.json()

        this.app.listen(this.port, (...params) => {
            if (typeof this.initFn === 'function') {
                this.initFn(...params)
            }
        })

        if (typeof this.rootFn === 'function') {
            this.app.get('/', this.rootFn)
        }

        const pwdToPermLevel = (pwd) => {
            if (typeof pwd !== 'string') {
                return 0
            }
            let permKey = Object.keys(this.permMap).find(x => x === pwd)
            if (permKey) {
                return this.permMap[permKey]
            }
            return 0
        }
        const checkPerms = (req, level) => {
            if (req === undefined || req.query === undefined || typeof req.query.pwd !== 'string') {
                return 400
            }
            let permLevel = pwdToPermLevel(req.query.pwd)
            if (level <= permLevel) {
                return 200
            }
            if (permLevel > 0) {
                return 401
            }
            return 403
        }
        this.app.get('/perms', (request, response) => {
            if (checkPerms(request, 1) === 400) {
                return response.status(400).json({})
            }
            response.send({
                level: pwdToPermLevel(request.query.pwd)
            })
        })

        const log = (...params) => {
            if (typeof this.log === 'function') {
                this.log(...params)
            } else if (this.log) {
                console.log(...params)
            }
        }

        if (!Array.isArray(this.getTable)) {
            this.getTable = []
        }
        this.getTable.forEach(item => {
            if (item === '' || item === 'perms') {
                log(`Warning! Will not re-define endpoint for "${item}"`)
            }
            this.app.get(`/${item.endpoint}`, async (request, response) => {
                log(`GET ${request.url}`)
                const perms = checkPerms(request, item.perms)
                if (perms !== 200) {
                    log(`\tReturn status code (Bad Auth): ${perms}`)
                    return response.status(perms).json({})
                }
                let res = await item.fn(request.query, request.url)
                if (res === undefined) {
                    res = {}
                }
                if (typeof res === 'object') {
                    response.send(res)
                } else {
                    log(`\tReturn status code: ${res}`)
                    return response.status(res).json({})
                }
            })
        })

        if (!Array.isArray(this.postTable)) {
            this.postTable = []
        }
        this.postTable.forEach(item => {
            this.app.post(`/${item.endpoint}`, this.jsonParser, async (request, response) => {
                log(`POST ${request.url}\r\n${JSON.stringify(request.body)}`)
                const perms = checkPerms(request, item.perms)
                if (perms !== 200) {
                    log(`\tReturn status code (Bad Auth): ${perms}`)
                    return response.status(perms).json({})
                }
                let res = await item.fn(request.body, pwdToPermLevel(request.query.pwd), request.query, request.url)
                if (typeof res !== 'number') {
                    res = 500
                    log('\tInternal Error!')
                }
                if (Math.floor(res / 100) != 2) {
                    log(`\tReturn status code: ${res}`)
                }
                return response.status(res).json({})
            })
        })
    }
}

module.exports = SimpleServer
