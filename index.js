require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const authRoute = require('./routes/routes');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const morgan = require('morgan');
const app = express();
const path = require('path');

//connect to mongoDB
mongoose.connect(process.env.DB_CONNECTION, { 
  useNewUrlParser: true, 
  useUnifiedTopology: true, 
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.log(err));

//middleware
app.use("/images",express.static("images"));
app.use(express.json());
app.use(cookieParser());
app.use(helmet());
app.use(morgan('common'));

app.use('/api/auth', authRoute);

const port = process.env.PORT || 8000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});