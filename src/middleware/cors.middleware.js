export const corsOptions = {
    origin: function (origin, callback) {
      const allowedOrigins = [
        'http://localhost:8080',
        'http://localhost:3000',
        'chrome-extension://ogajmmpomfocfpjhalbfjhjeikidgkef',
      ];
      
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    methods: 'GET,POST',
    allowedHeaders: 'Content-Type,Authorization',
  };
  