import express, { Application, Request, Response } from 'express';

const app: Application = express();
const PORT = 3000;

app.get('/health', (req: Request, res: Response) => {
  res.send({test:"hello"});
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
