import { Response } from 'express'

export function getBadRequestError(res: Response, message: string) {
  return res.status(400).json({
    message: [message],
    statusCode: 400,
    error: 'Bad Request',
  })
}
