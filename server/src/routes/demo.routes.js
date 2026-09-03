// src/routes/demo.routes.js
import { Router } from 'express';
import * as demoController from '../controllers/demo.controller.js';

const router = Router();

router.post('/book', demoController.bookDemo);

export default router;
