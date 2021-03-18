const {Router} = require('express');
const authConterller = require('../controllers/authControllers');

const router = Router();

router.get('/login',authConterller.login_get);
//router.post('/login', authConterller.login_post);
//router.get('/logout',authConterller.logout_get);




module.exports = router;