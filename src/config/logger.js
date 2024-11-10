// src/config/logger.js
import { createLogger, format, transports } from 'winston';

const logger = createLogger({
  level: process.env.LOG_LEVEL || 'debug',
  format: format.combine(
    format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    format.errors({ stack: true }),
    format.splat(),
    format.json(),
    format.printf(({ timestamp, level, message, ...meta }) => {
      let log = `${timestamp} [${level}]: ${message}`;
      if (Object.keys(meta).length) {
        log += `\n${JSON.stringify(meta, null, 2)}`;
      }
      return log;
    })
  ),
  transports: [
    new transports.Console({
      level: 'debug',
      format: format.combine(
        format.colorize(),
        format.simple()
      )
    }),
    new transports.File({
      filename: 'logs/error.log',
      level: 'error'
    }),
    new transports.File({
      filename: 'logs/debug.log',
      level: 'debug'
    }),
    new transports.File({
      filename: 'logs/combined.log',
      level: 'debug'
    })
  ]
});

logger.debugWithContext = (message, context) => {
  logger.debug(message, { context: JSON.stringify(context, null, 2) });
};

export default logger;