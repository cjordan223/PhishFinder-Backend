import winston from 'winston';
const { createLogger, format, transports } = winston;

// Add new transport for Safe Browsing logs
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
    }),
    // Add new transport for Safe Browsing logs
    new transports.File({
      filename: 'logs/safebrowsing.log',
      level: 'debug',
      format: format.combine(
        format.label({ label: 'SAFE_BROWSING' }),
        format.printf(({ timestamp, level, message, label, ...meta }) => {
          let log = `${timestamp} [${label}] [${level}]: ${message}`;
          if (Object.keys(meta).length) {
            log += `\n${JSON.stringify(meta, null, 2)}`;
          }
          return log;
        })
      )
    })
  ]
});

// Add helper method for Safe Browsing logs
logger.safeBrowsing = (message, meta) => {
  logger.log({
    level: 'debug',
    message,
    label: 'SAFE_BROWSING',
    ...meta
  });
};

export default logger;