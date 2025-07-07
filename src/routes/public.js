// Core modules

// External modules
const express = require('express')

// Modules

// Router
let router = express.Router()

router.get('/', async (req, res, next) => {
    try {
        res.render('home.html')
    } catch (err) {
        next(err)
    }
});
router.get('/apps/countdown', async (req, res, next) => {
    try {
        res.render('countdown.html')
    } catch (err) {
        next(err)
    }
});

module.exports = router;