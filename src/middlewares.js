
// Core modules

// External modules
const access = require('acrb')
const lodash = require('lodash');

// Modules


module.exports = {
    rateLimit: (delay = 0) => {
        return async (req, res, next) => {
            try {
                await new Promise(resolve => setTimeout(resolve, delay))
                next();
            } catch (err) {
                next(err)
            }
        }
    },
    allowIp: async (req, res, next) => {
        try {
            if (CONFIG.ipCheck === false) {
                return next();
            }

            let ips = await req.app.locals.db.models.AllowedIP.findAll(); // Get from db
            let allowed = lodash.map(ips, (ip) => { // Simplify
                return ip.address;
            })

            if (allowed.length <= 0) { // If none from db, get from config
                allowed = CONFIG.ip.allowed;
            }
            let ip = req.headers['x-real-ip'] || req.connection.remoteAddress;

            if (allowed.includes(ip) || allowed.length <= 0) {
                return next();
            }
            res.setHeader('X-IP', ip);
            res.status(400).send('Access denied from ' + ip)
        } catch (err) {
            next(err);
        }
    },
    antiCsrfCheck: async (req, res, next) => {
        try {
            let acsrf = lodash.get(req, 'body.acsrf')

            if (lodash.get(req, 'session.acsrf') === acsrf) {
                return next();
            }
            throw new Error(`Anti-CSRF error detected.`)
        } catch (err) {
            next(err);
        }
    },
    guardRoute: (permissions, condition = 'and') => {
        return async (req, res, next) => {
            try {
                let user = res.user
                let rolesList = await req.app.locals.db.models.Role.findAll()
                if (condition === 'or') {
                    if (!access.or(user, permissions, rolesList)) {
                        return res.render('error.html', {
                            error: `Access denied. Must have one of these permissions: ${permissions.join(', ')}.`
                        })
                    }
                } else {
                    if (!access.and(user, permissions, rolesList)) {
                        return res.render('error.html', {
                            error: `Access denied. Required all these permissions: ${permissions.join(', ')}.`
                        })
                    }
                }
                next()
            } catch (err) {
                next(err)
            }
        }
    },
    

    requireAuthUser: async (req, res, next) => {
        try {
            let authUserId = lodash.get(req, 'session.authUserId')
            if (!authUserId) {
                return res.redirect('/login')
            }
            let user = await req.app.locals.db.models.User.findOne({
                where: {
                    id: authUserId
                },
            })

            if (!user) {
                return res.redirect('/logout') // Prevent redirect loop when user is null
            }
            if (!user.active) {
                return res.redirect('/logout')
            }
            res.user = user
            next()
        } catch (err) {
            next(err)
        }
    },
    requireAuthAdmin: async (req, res, next) => {
        try {
            let authUserId = lodash.get(req, 'session.authUserId')
            if (!authUserId) {
                return res.redirect('/admin-login')
            }
            let user = await req.app.locals.db.models.User.findOne({
                where: {
                    id: authUserId
                },
            })

            if (!user) {
                return res.redirect('/logout') // Prevent redirect loop when user is null
            }
            if (!user.active) {
                return res.redirect('/logout')
            }
            res.user = user
            next()
        } catch (err) {
            next(err)
        }
    },
    requireAuthViewer: async (req, res, next) => {
        try {
            let authUserId = lodash.get(req, 'session.authUserId') // User login
            let authPasscodeId = lodash.get(req, 'session.authPasscodeId') // Passcode

            if (!authUserId && !authPasscodeId) {
                return res.redirect('/')
            }

            next()
        } catch (err) {
            next(err)
        }
    },
    /**
     * See: https://expressjs.com/en/api.html#app.locals
     * See: https://expressjs.com/en/api.html#req.app
     * 
     * @param {*} req 
     * @param {*} res 
     * @param {*} next 
     */
    perAppViewVars: function (req, res, next) {
        req.app.locals.app = {
            title: CONFIG.app.title,
            description: CONFIG.description,
            url: ''
        }
        req.app.locals.CONFIG = lodash.cloneDeep(CONFIG) // Config
        req.app.locals.ENV = ENV
        req.app.locals.VERSION = `2023.11`
        req.app.locals.SERVER_URL = CONFIG.app.url,
            req.app.locals.SOCKET_URL = `//${req.headers['host']}`,

            next()
    },
    /**
     * See: https://expressjs.com/en/api.html#res.locals
     * 
     * @param {*} req 
     * @param {*} res 
     * @param {*} next 
     */
    perRequestViewVars: async (req, res, next) => {
        try {
            res.locals.user = null
            let authUserId = lodash.get(req, 'session.authUserId');
            if (authUserId) {
                let user = await req.app.locals.db.models.User.findByPk(authUserId)
                if (user) {
                    user = user.toJSON() // Plain object
                    user = lodash.pickBy(user, (_, key) => {
                        return !['createdAt', 'updatedAt', '__v', 'passwordHash', 'salt'].includes(key) // Remove these props
                    })
                }
                res.locals.user = user
            }

            res.locals.acsrf = lodash.get(req, 'session.acsrf');

            res.locals.url = req.url
            res.locals.urlPath = req.path
            res.locals.query = req.query

            let bodyClass = 'page' + (req.baseUrl + req.path).replace(/\//g, '-');
            bodyClass = lodash.trim(bodyClass, '-');
            bodyClass = lodash.trimEnd(bodyClass, '.html');
            res.locals.bodyClass = bodyClass; // global body class css

            res.locals.hideNav = lodash.get(req, 'cookies.hideNav', 'true')

            next();
        } catch (error) {
            next(error);
        }
    },
    saneTitles: async (req, res, next) => {
        try {
            if (!res.locals.title && !req.xhr) {
                let title = lodash.trim(req.originalUrl.split('/').join(' '));
                title = lodash.trim(title.replace('-', ' '));
                let words = lodash.map(title.split(' '), (word) => {
                    return lodash.capitalize(word);
                })
                title = words.join(' - ')
                if (title) {
                    res.locals.title = `${title} | ${req.app.locals.app.title} `;
                }
            }
            next();
        } catch (error) {
            next(error);
        }
    },
}