// G2 server-entry fixture (po-av01j.3): express route/middleware
// registrations and NestJS route decorators. Registrations must emit as
// site_kind "server_entry" and never as G1 client calls.
import express from 'express';
import { Controller, Get } from '@nestjs/common';

const app = express();
const router = express.Router();

app.get('/healthz', (req, res) => res.status(200).send('ok'));
app.use(requestLogger());
router.post('/users', (req, res) => res.send('created'));
app.listen(3000);

function requestLogger(): any {
  return (_req: any, _res: any, next: () => void) => next();
}

@Controller('orders')
export class OrdersController {
  @Get('/orders')
  list(): any[] {
    return [];
  }
}
