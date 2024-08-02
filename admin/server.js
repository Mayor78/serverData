const express = require('express');
const app = express();
const port = process.env.PORT || 3000;

// Middleware and routes
app.use(express.json());

// Example route
app.get('/api/test', (req, res) => {
  res.json({ message: 'API is working' });
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
